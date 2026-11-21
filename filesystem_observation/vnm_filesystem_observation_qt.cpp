#include "vnm_filesystem_observation_qt.h"
#include "vnm_filesystem_observation_variant.h"

#include <vnm_qt_dispatch/vnm_qt_dispatch.h>

#include <mutex>
#include <stdexcept>
#include <utility>

VNM_FILESYSTEM_OBSERVATION_REFERENCE_VARIANT(qt_channel)

namespace vnm::filesystem_observation {

struct Qt_delivery::State
{
    struct Pending
    {
        std::optional<Delivery> delivery;
    };

    std::mutex mutex;
    QObject* receiver = nullptr;
    std::function<void(Delivery)> callback;
    std::weak_ptr<Pending> pending;
};

Qt_delivery::Qt_delivery(QObject* receiver, std::function<void(Delivery)> callback)
:
    m_state(std::make_shared<State>())
{
    if (!receiver || !callback || !vnm::qt::is_current_thread(receiver->thread())) {
        throw std::invalid_argument("Qt observation delivery requires a live receiver on the calling thread");
    }
    m_state->receiver = receiver;
    m_state->callback = std::move(callback);
}

Qt_delivery::~Qt_delivery() { cancel(); }

void Qt_delivery::submit(Delivery delivery)
{
    std::lock_guard lock(m_state->mutex);
    if (!m_state->receiver || !delivery.valid()) {
        return;
    }
    auto pending = std::make_shared<State::Pending>();
    pending->delivery.emplace(std::move(delivery));
    m_state->pending = pending;
    // The owned delivery releases its slot even if Qt drops the queued event.
    const auto result = vnm::qt::post(m_state->receiver,
        [state = m_state, pending = std::move(pending)]() mutable {
            std::function<void(Delivery)> callback;
            std::optional<Delivery> delivery;
            {
                std::lock_guard callback_lock(state->mutex);
                if (!state->receiver || !pending->delivery || !pending->delivery->valid()) {
                    return;
                }
                delivery = std::move(pending->delivery);
                pending->delivery.reset();
                state->pending.reset();
                callback = state->callback;
            }
            callback(std::move(*delivery));
        });
    if (result != vnm::qt::Post_result::QUEUED) {
        qWarning("Filesystem observation: Qt delivery submission failed (%d)", int(result));
    }
}

void Qt_delivery::cancel()
{
    std::lock_guard lock(m_state->mutex);
    m_state->receiver = nullptr;
    m_state->callback = {};
    if (const auto pending = m_state->pending.lock()) {
        pending->delivery.reset();
    }
    m_state->pending.reset();
}

} // namespace vnm::filesystem_observation
