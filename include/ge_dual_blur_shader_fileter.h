#pragma once

#include "filterbase.h"
#include <memory>

namespace snapdragon::filters {

class DualBlurFilter : public FilterBase {
public:
    DualBlurFilter();
    ~DualBlurFilter();

    bool load() override;
    void render(FrameBuffer* source) override;

private:
    std::unique_ptr<Material> downsampleMaterial_;
    std::unique_ptr<Material> upsampleMaterial_;
    int levels_;
};

} // namespace snapdragon::filters
