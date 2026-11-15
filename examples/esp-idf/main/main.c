/*
 * Connectivitizer with ESP-IDF, without Arduino: a small HTTP server (esp_http_server) that is
 * reachable from your app through Connectivitizer.
 *
 * Fill in the five values below, then: idf.py set-target esp32c3 (or your chip), idf.py flash monitor
 */
#include <stdio.h>
#include <string.h>

#include "cz.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#define WIFI_SSID "your-wifi"
#define WIFI_PASSWORD "your-wifi-password"
#define DEVICE_KEY "czd_..."            /* from your workspace */
#define DEVICE_NAME "living-room-lamp"  /* how your app addresses this device */
#define SHARED_KEY "czs_..."            /* the same key your app has; never sent to anyone */

static const char *TAG = "example";

static esp_err_t state_handler(httpd_req_t *request)
{
    char json[96];
    snprintf(json, sizeof json, "{\"uptimeSeconds\":%u,\"freeHeap\":%u}",
             (unsigned)(xTaskGetTickCount() * portTICK_PERIOD_MS / 1000), (unsigned)esp_get_free_heap_size());
    httpd_resp_set_type(request, "application/json");
    return httpd_resp_sendstr(request, json);
}

static void on_wifi_event(void *argument, esp_event_base_t base, int32_t id, void *data)
{
    /* Connect, and connect again whenever the connection is lost. */
    if (base == WIFI_EVENT && (id == WIFI_EVENT_STA_START || id == WIFI_EVENT_STA_DISCONNECTED)) {
        esp_wifi_connect();
    }
}

static void log_line(const char *line, void *user)
{
    ESP_LOGI("connectivitizer", "%s", line);
}

static void connectivitizer_task(void *argument)
{
    cz_agent_run((cz_agent *)argument);
    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event, NULL));
    wifi_config_t wifi = { 0 };
    strncpy((char *)wifi.sta.ssid, WIFI_SSID, sizeof wifi.sta.ssid - 1);
    strncpy((char *)wifi.sta.password, WIFI_PASSWORD, sizeof wifi.sta.password - 1);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* An ordinary HTTP server. It knows nothing about Connectivitizer. */
    httpd_handle_t server = NULL;
    httpd_config_t http = HTTPD_DEFAULT_CONFIG();
    ESP_ERROR_CHECK(httpd_start(&server, &http));
    httpd_uri_t state = { .uri = "/state", .method = HTTP_GET, .handler = state_handler };
    httpd_register_uri_handler(server, &state);

    cz_config config = { 0 };
    config.device_key = DEVICE_KEY;
    config.name = DEVICE_NAME;
    config.shared_keys[0] = SHARED_KEY;
    config.services[0].name = "api";      /* the HTTP server above, under the name "api" */
    config.services[0].port = 80;
    config.services[0].protocol = "http";
    config.log = log_line;

    cz_agent *agent = cz_agent_create(&config);
    if (agent == NULL) {
        ESP_LOGE(TAG, "check DEVICE_KEY, DEVICE_NAME and SHARED_KEY");
        return;
    }
    /* The TLS handshakes with the platform run on this task; they are what needs the stack. */
    xTaskCreate(connectivitizer_task, "connectivitizer", 16384, agent, 5, NULL);
}
