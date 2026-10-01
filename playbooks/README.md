# Playbooks

Checks are YAML, not code, so the debugging methodology stays reviewable.
Each playbook maps intent (source DB + key pattern) to reality (target DB via
a key-map), lists compared fields, correlation sources, and the mechanical
stage rule applied on divergence. Executor is hackathon-window work.
