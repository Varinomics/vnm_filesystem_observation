#pragma once

#include "vnm_filesystem_observation.h"

#include <QObject>

#include <functional>
#include <memory>

namespace vnm::filesystem_observation {

// Construct on the receiver thread. Call cancel() at the start of the receiver's
// destructor, before any callback-visible members die. cancel() serializes against
// submission; QObject destruction alone cannot make a raw pointer safe to post to.
class Qt_delivery final : public Delivery_channel
{
public:
    Qt_delivery(QObject* receiver, std::function<void(Delivery)> callback);
    ~Qt_delivery() override;
    void submit(Delivery delivery) override;
    void cancel() override;

private:
    struct State;
    std::shared_ptr<State> m_state;
};

} // namespace vnm::filesystem_observation
