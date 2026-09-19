#include "common/runtime_state.h"
#include "vm/pvm2_format.h"

#include <cstring>

namespace protector {

CodeItem::CodeItem() = default;

CodeItem::~CodeItem() {
    if (!vm_image.empty()) {
        memset(vm_image.data(), 0, vm_image.size());
        vm_image.clear();
    }
    parsed_vm.reset();
}

RuntimeState& runtime_state() {
    static RuntimeState state;
    return state;
}

} // namespace protector
