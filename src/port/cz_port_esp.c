/*
 * The port for ESP32 (ESP-IDF and the Arduino core, which is built on it). It uses only what
 * every version of the board package contains: lwIP sockets, esp-tls for the connections to the
 * platform, the hardware random generator and FreeRTOS.
 */
#if defined(ESP_PLATFORM)

#include "cz_port.h"

#include <stdlib.h>
#include <string.h>

#include "esp_idf_version.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/netif.h"
#include "sdkconfig.h"

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
#include "esp_random.h"
#endif

#include "cz_roots.h"

struct cz_conn {
    esp_tls_t *tls;
    int fd;
    bool secure;
};

cz_conn *cz_conn_open(const char *host, uint16_t port, bool tls, const char *root_ca_pem, int timeout_ms)
{
    cz_conn *conn = (cz_conn *)calloc(1, sizeof *conn);
    if (conn == NULL) {
        return NULL;
    }
    conn->secure = tls;
    if (!tls) {
        conn->fd = cz_tcp_connect(host, port, timeout_ms);
        if (conn->fd < 0) {
            free(conn);
            return NULL;
        }
        return conn;
    }

    esp_tls_cfg_t config;
    memset(&config, 0, sizeof config);
    config.timeout_ms = timeout_ms;
    /* The platform's certificate must chain to an authority this device trusts: the application's own, or the built-in ones. */
    const char *roots = root_ca_pem != NULL ? root_ca_pem : cz_default_roots;
    config.cacert_pem_buf = (const unsigned char *)roots;
    config.cacert_pem_bytes = strlen(roots) + 1;

    conn->tls = esp_tls_init();
    if (conn->tls == NULL || esp_tls_conn_new_sync(host, (int)strlen(host), port, &config, conn->tls) != 1) {
        if (conn->tls != NULL) {
            esp_tls_conn_destroy(conn->tls);
        }
        free(conn);
        return NULL;
    }
    if (esp_tls_get_conn_sockfd(conn->tls, &conn->fd) != ESP_OK) {
        esp_tls_conn_destroy(conn->tls);
        free(conn);
        return NULL;
    }
    cz_socket_set_nonblocking(conn->fd);
    return conn;
}

int cz_conn_fd(const cz_conn *conn)
{
    return conn->fd;
}

bool cz_conn_pending(cz_conn *conn)
{
    return conn->secure && esp_tls_get_bytes_avail(conn->tls) > 0;
}

int cz_conn_read(cz_conn *conn, uint8_t *out, int capacity)
{
    if (!conn->secure) {
        int received = (int)recv(conn->fd, out, (size_t)capacity, 0);
        if (received > 0) {
            return received;
        }
        return received < 0 && cz_socket_would_block() ? 0 : -1;
    }
    int received = (int)esp_tls_conn_read(conn->tls, out, (size_t)capacity);
    if (received > 0) {
        return received;
    }
    if (received == ESP_TLS_ERR_SSL_WANT_READ || received == ESP_TLS_ERR_SSL_WANT_WRITE) {
        return 0;
    }
    return -1;
}

bool cz_conn_write(cz_conn *conn, const uint8_t *data, size_t size, int timeout_ms)
{
    uint32_t started = cz_millis();
    while (size > 0) {
        int sent;
        bool retry;
        if (conn->secure) {
            sent = (int)esp_tls_conn_write(conn->tls, data, size);
            retry = sent == ESP_TLS_ERR_SSL_WANT_READ || sent == ESP_TLS_ERR_SSL_WANT_WRITE;
        } else {
            sent = (int)send(conn->fd, data, size, 0);
            retry = sent < 0 && cz_socket_would_block();
        }
        if (sent > 0) {
            data += sent;
            size -= (size_t)sent;
            continue;
        }
        if (!retry || (int)(cz_millis() - started) > timeout_ms) {
            return false;
        }
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(conn->fd, &writable);
        struct timeval wait = { 0, 50 * 1000 };
        select(conn->fd + 1, NULL, &writable, NULL, &wait);
    }
    return true;
}

void cz_conn_close(cz_conn *conn)
{
    if (conn == NULL) {
        return;
    }
    if (conn->secure) {
        esp_tls_conn_destroy(conn->tls);
    } else {
        cz_socket_close(conn->fd);
    }
    free(conn);
}

uint32_t cz_millis(void)
{
    return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

void cz_sleep_ms(int milliseconds)
{
    vTaskDelay(pdMS_TO_TICKS(milliseconds > 0 ? milliseconds : 1));
}

void cz_random(uint8_t *out, size_t size)
{
    /* The hardware generator; it is a true random source while Wi-Fi or Bluetooth is running. */
    esp_fill_random(out, size);
}

const char *cz_platform_name(void)
{
    return "esp32 (" CONFIG_IDF_TARGET ")";
}

uint32_t cz_local_address(void)
{
    /* The address of the interface that carries the default route (Wi-Fi, or Ethernet on boards
       that have it). The trick of the host port does not work here: lwIP leaves the local address
       of a connected UDP socket at 0.0.0.0. */
    struct netif *netif = netif_default;
    if (netif == NULL || !netif_is_up(netif) || !netif_is_link_up(netif)) {
        return 0;
    }
    return ip4_addr_get_u32(netif_ip4_addr(netif));
}

void cz_ipv6_enable(void)
{
#if defined(CZ_IPV6)
    static bool enabled = false;
    if (enabled) {
        return;
    }
    /* Arduino and ESP-IDF leave IPv6 off until an application asks for it. A link-local address
       is the first step; the router's announcements then give the global ones (SLAAC). */
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif == NULL) {
        netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
    }
    if (netif != NULL && esp_netif_create_ip6_linklocal(netif) == ESP_OK) {
        enabled = true;
    }
#endif
}

int cz_local_ipv6(uint8_t (*out)[16], int max)
{
    int count = 0;
#if defined(CZ_IPV6)
    struct netif *netif = netif_default;
    if (netif == NULL || !netif_is_up(netif)) {
        return 0;
    }
    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES && count < max; i++) {
        const ip6_addr_t *address = netif_ip6_addr(netif, i);
        if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) && ip6_addr_isglobal(address)) {
            memcpy(out[count++], address->addr, 16);
        }
    }
#else
    (void)out;
    (void)max;
#endif
    return count;
}

#endif
