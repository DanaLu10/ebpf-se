#ifndef __VERIFY_H
#define __VERIFY_H

static __always_inline void addDependency(void *dependentMap, void *headMap) {
  struct bpf_map_def *dependentPtr = ((struct bpf_map_def *)dependentMap);
  struct bpf_map_def *headPtr = ((struct bpf_map_def *)headMap);

  dependentPtr->dependent_on = headPtr;
  headPtr->head_to = dependentPtr;
}

#endif // __VERIFY_H