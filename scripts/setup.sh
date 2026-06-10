#!/bin/bash

set -e
# To run this script you need to run the following command in a separate terminals:
#   > kli witness demo

# EMN3HVTrF7Vs68L_xewuc2m33VH-N-rQnNtwuWu8JXjR
kli init --name keriguard --salt 0ACDEyMzQ1Njc4OWxtbm9GhI --nopasscode --config-dir "${KERIGUARD_SCRIPT_DIR}" --config-file registrar-config
kli incept --name keriguard --alias keriguard --file "${KERIGUARD_SCRIPT_DIR}/data/base-aid.json"
kli init --name keriguard-sentinel --salt 0ACDEyMzQ1Njc4OWxtbm9kgs --config-dir "${KERIGUARD_SCRIPT_DIR}" --config-file registrar-config --nopasscode
kli incept --name keriguard-sentinel --alias keriguard-sentinel --icount 1 --isith "1" --ncount 1 --nsith "1" --toad 0
kli export --name keriguard-sentinel --alias keriguard-sentinel --ends > /tmp/keriguard-sentinel.cesr

kli init --name admin --salt 0ACDEyMzQ1Njc4OWxtbm9admin --nopasscode --config-dir "${KERIGUARD_SCRIPT_DIR}" --config-file registrar-config
kli incept --name admin --alias admin --file "${KERIGUARD_SCRIPT_DIR}"/data/base-aid.json

kli init --name registrar --salt 0ACDEyMzQ1Njc4OWxtbm9reg --config-dir "${KERIGUARD_SCRIPT_DIR}" --config-file registrar-config --nopasscode
kli incept --name registrar --alias registrar --icount 1 --isith "1" --ncount 1 --nsith "1" --toad 0 --config "${KERIGUARD_SCRIPT_DIR}"
kli export --name registrar --alias registrar --ends > /tmp/registrar.cesr
kli init --name registrar-sentinel --salt 0ACDEyMzQ1Njc4OWxtbm9kgs --config-dir "${KERIGUARD_SCRIPT_DIR}" --config-file registrar-config --nopasscode
kli incept --name registrar-sentinel --alias registrar-sentinel --icount 1 --isith "1" --ncount 1 --nsith "1" --toad 0
kli export --name registrar-sentinel --alias registrar-sentinel --ends > /tmp/registrar-sentinel.cesr

kli init --name peer --salt 0ACDEyMzQ1Njc4OWxtbmPeer --nopasscode --config-dir "${KERIGUARD_SCRIPT_DIR}" --config-file registrar-config
kli incept --name peer --alias peer --file "${KERIGUARD_SCRIPT_DIR}/data/base-aid.json"

echo "Importing the KERIGuard Schema"
kli vc schema import --name keriguard --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-interface-v1.0.0.json"
kli vc schema import --name keriguard --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-connection-v1.0.0.json"
kli vc schema import --name keriguard-sentinel --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-interface-v1.0.0.json"
kli vc schema import --name keriguard-sentinel --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-connection-v1.0.0.json"
kli vc schema import --name registrar --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-interface-v1.0.0.json"
kli vc schema import --name registrar --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-connection-v1.0.0.json"
kli vc schema import --name registrar-sentinel --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-interface-v1.0.0.json"
kli vc schema import --name registrar-sentinel --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-connection-v1.0.0.json"
kli vc schema import --name admin --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-interface-v1.0.0.json"
kli vc schema import --name admin --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-connection-v1.0.0.json"
kli vc schema import --name peer --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-interface-v1.0.0.json"
kli vc schema import --name peer --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-connection-v1.0.0.json"

kli vc registry incept --name admin --alias admin --registry-name admin

echo 'resolving keriguard'
kli oobi resolve --name admin --oobi-alias keriguard --oobi http://127.0.0.1:5642/oobi/EMukoPLVfJ2sxulTtaAf4oTyNESAeoZGEkrEXT8JXjf0/witness
kli oobi resolve --name keriguard-sentinel --oobi-alias keriguard --oobi http://127.0.0.1:5642/oobi/EMukoPLVfJ2sxulTtaAf4oTyNESAeoZGEkrEXT8JXjf0/witness
echo 'resolving admin'
kli oobi resolve --name keriguard --oobi-alias admin --oobi http://127.0.0.1:5642/oobi/EI6-tTwfonE2nKknuUkhkwRe-Op7kTYIeCUJcuuMUFUr/witness
kli oobi resolve --name registrar --oobi-alias admin --oobi http://127.0.0.1:5642/oobi/EI6-tTwfonE2nKknuUkhkwRe-Op7kTYIeCUJcuuMUFUr/witness
kli oobi resolve --name peer --oobi-alias admin --oobi http://127.0.0.1:5642/oobi/EI6-tTwfonE2nKknuUkhkwRe-Op7kTYIeCUJcuuMUFUr/witness
echo 'resolving peer'
kli oobi resolve --name admin --oobi-alias peer --oobi http://127.0.0.1:5642/oobi/EK9MXvIlVUcs9sztuX3oTJkBq-BqdKUxyLZmiOqXWZ8u/witness
echo 'resolving registrar'
kli import --name keriguard --alias registrar --file /tmp/registrar.cesr
kli import --name registrar-sentinel --alias registrar --file /tmp/registrar.cesr
kli import --name admin --alias registrar --file /tmp/registrar.cesr
echo 'resolving sentinels'
kli import --name keriguard --alias keriguard-sentinel --file /tmp/keriguard-sentinel.cesr
kli import --name registrar --alias registrar-sentinel --file /tmp/registrar-sentinel.cesr
