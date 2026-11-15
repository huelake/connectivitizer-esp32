#include "Connectivitizer.h"

#if defined(ESP_PLATFORM)

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

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

const char *ConnectivitizerClass::lastError()
{
    if (_agent == nullptr) {
        return "";
    }
    cz_agent_get_status(_agent, &_status);
    return _status.last_error;
}

#endif
