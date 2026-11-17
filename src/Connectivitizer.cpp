#include "Connectivitizer.h"

#if defined(ESP_PLATFORM)

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <string.h>

#if defined(ARDUINO)
#include "lwip/sockets.h"
#endif

/* The TLS handshakes with the platform run on this task; they are what needs the stack. */
#ifndef CZ_TASK_STACK
#define CZ_TASK_STACK 16384
#endif
#ifndef CZ_TASK_PRIORITY
#define CZ_TASK_PRIORITY 5
#endif

ConnectivitizerClass Connectivitizer;

static void cz_task(void *argument)
{
    cz_agent_run(static_cast<cz_agent *>(argument));
    vTaskSuspend(nullptr); /* end() deletes the task */
}

void ConnectivitizerClass::setServer(const char *apiUrl)
{
    _config.api_url = apiUrl;
}

bool ConnectivitizerClass::setSharedKey(const char *key)
{
    if (_keys >= CZ_MAX_SHARED_KEYS) {
        return false;
    }
    _config.shared_keys[_keys++] = key;
    return true;
}

bool ConnectivitizerClass::expose(const char *name, uint16_t port, const char *host, const char *protocol)
{
    if (_services >= CZ_MAX_SERVICES) {
        return false;
    }
    _config.services[_services].name = name;
    _config.services[_services].port = port;
    _config.services[_services].host = host;
    _config.services[_services].protocol = protocol;
    _services++;
    return true;
}

bool ConnectivitizerClass::link(const char *device, const char *service, uint16_t localPort, const char *sharedKey)
{
    if (_links >= CZ_MAX_LINKS || _agent != nullptr) {
        return false;
    }
    _config.links[_links].device = device;
    _config.links[_links].service = service;
    _config.links[_links].local_port = localPort;
    _config.links[_links].shared_key = sharedKey;
    _links++;
    return true;
}

uint16_t ConnectivitizerClass::linkPort(const char *device, const char *service)
{
    for (int i = 0; i < _links; i++) {
        if (strcmp(_config.links[i].device, device) == 0 && (service == nullptr || strcmp(_config.links[i].service, service) == 0)) {
            return _config.links[i].local_port;
        }
    }
    return 0;
}

#if defined(ARDUINO)
/*
 * A plain HTTP/1.0 request to a link's port. HTTP/1.0 keeps the answer simple: the body is what
 * follows the header until the other side closes the connection.
 */
int ConnectivitizerClass::request(const char *method, const char *device, const char *path, const String *body, const char *contentType, String &response, uint32_t timeoutMs)
{
    response = "";
    uint16_t port = linkPort(device);
    if (port == 0) {
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return -1;
    }
    struct timeval wait = { (long)(timeoutMs / 1000), (long)(timeoutMs % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &wait, sizeof wait);
    struct sockaddr_in local;
    memset(&local, 0, sizeof local);
    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = htonl(0x7f000001u);
    if (connect(fd, (struct sockaddr *)&local, sizeof local) != 0) {
        close(fd);
        return -1;
    }

    String head = String(method) + " " + path + " HTTP/1.0\r\nHost: " + device + "\r\n";
    if (body != nullptr) {
        head += String("Content-Type: ") + contentType + "\r\nContent-Length: " + String(body->length()) + "\r\n";
    }
    head += "\r\n";
    bool sent = send(fd, head.c_str(), head.length(), 0) == (int)head.length();
    for (size_t at = 0; sent && body != nullptr && at < body->length();) {
        int count = send(fd, body->c_str() + at, body->length() - at, 0);
        sent = count > 0;
        at += sent ? (size_t)count : 0;
    }

    String answer;
    char buffer[256];
    uint32_t started = millis();
    while (sent && millis() - started < timeoutMs) {
        int count = recv(fd, buffer, sizeof buffer, 0);
        if (count <= 0) {
            break;
        }
        answer.concat(buffer, (unsigned int)count);
    }
    close(fd);

    /* "HTTP/1.x <status> ..." and, after an empty line, the body. */
    int headEnd = answer.indexOf("\r\n\r\n");
    if (!answer.startsWith("HTTP/") || headEnd < 0 || answer.length() < 12) {
        return -1;
    }
    response = answer.substring(headEnd + 4);
    return answer.substring(9, 12).toInt();
}

int ConnectivitizerClass::get(const char *device, const char *path, String &response, uint32_t timeoutMs)
{
    return request("GET", device, path, nullptr, nullptr, response, timeoutMs);
}

int ConnectivitizerClass::post(const char *device, const char *path, const String &body, String &response, uint32_t timeoutMs, const char *contentType)
{
    return request("POST", device, path, &body, contentType, response, timeoutMs);
}
#endif

void ConnectivitizerClass::setPeerToPeer(bool enabled)
{
    _config.disable_peer_to_peer = !enabled;
}

void ConnectivitizerClass::setRootCA(const char *pem)
{
    _config.root_ca_pem = pem;
}

#if defined(ARDUINO)
static void cz_print(const char *line, void *user)
{
    static_cast<Print *>(user)->println(line);
}

void ConnectivitizerClass::setLog(Print &out)
{
    _config.log = cz_print;
    _config.log_user = &out;
}
#endif

bool ConnectivitizerClass::begin(const char *deviceKey, const char *name)
{
    if (_agent != nullptr) {
        return true;
    }
    _config.device_key = deviceKey;
    _config.name = name;
    _agent = cz_agent_create(&_config);
    if (_agent == nullptr) {
        return false;
    }
    TaskHandle_t task = nullptr;
    if (xTaskCreate(cz_task, "connectivitizer", CZ_TASK_STACK, _agent, CZ_TASK_PRIORITY, &task) != pdPASS) {
        cz_agent_destroy(_agent);
        _agent = nullptr;
        return false;
    }
    _task = task;
    return true;
}

void ConnectivitizerClass::end()
{
    if (_agent == nullptr) {
        return;
    }
    cz_agent_stop(_agent);
    /* The task notices within one pass of its loop; connecting can take a few seconds longer. */
    for (int i = 0; i < 300 && eTaskGetState(static_cast<TaskHandle_t>(_task)) != eSuspended; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    vTaskDelete(static_cast<TaskHandle_t>(_task));
    cz_agent_destroy(_agent);
    _agent = nullptr;
    _task = nullptr;
}

bool ConnectivitizerClass::connected()
{
    if (_agent == nullptr) {
        return false;
    }
    cz_agent_get_status(_agent, &_status);
    return _status.state == CZ_STATE_ONLINE;
}

bool ConnectivitizerClass::refused()
{
    if (_agent == nullptr) {
        return false;
    }
    cz_agent_get_status(_agent, &_status);
    return _status.state == CZ_STATE_REFUSED;
}

int ConnectivitizerClass::sessions()
{
    if (_agent == nullptr) {
        return 0;
    }
    cz_agent_get_status(_agent, &_status);
    return _status.sessions;
}

int ConnectivitizerClass::links()
{
    if (_agent == nullptr) {
        return 0;
    }
    cz_agent_get_status(_agent, &_status);
    return _status.links;
}

const char *ConnectivitizerClass::lastError()
{
    if (_agent == nullptr) {
        return "";
    }
    cz_agent_get_status(_agent, &_status);
    return _status.last_error;
}

#endif
