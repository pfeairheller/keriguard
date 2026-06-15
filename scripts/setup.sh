#!/bin/bash

set -e
# To run this script you need to run the following command in a separate terminals:
#   > kli witness demo

kli init --name admin --salt 0ACDEyMzQ1Njc4OWxtbm9admin --nopasscode --config-dir "${KERIGUARD_SCRIPT_DIR}" --config-file registrar-config
kli incept --name admin --alias admin --file "${KERIGUARD_SCRIPT_DIR}"/data/base-aid.json

kli init --name registrar --salt 0ACDEyMzQ1Njc4OWxtbm9reg --nopasscode --config-dir "${KERIGUARD_SCRIPT_DIR}" --config-file registrar-config
kli incept --name registrar --alias registrar --file "${KERIGUARD_SCRIPT_DIR}"/data/base-aid.json
kli init --name registrar-sentinel --salt 0ACDEyMzQ1Njc4OWxtbm9kgs --config-dir "${KERIGUARD_SCRIPT_DIR}" --config-file registrar-config --nopasscode
kli incept --name registrar-sentinel --alias registrar-sentinel --icount 1 --isith "1" --ncount 1 --nsith "1" --toad 0
kli export --name registrar-sentinel --alias registrar-sentinel --ends > /tmp/registrar-sentinel.cesr

echo REGISTRAR AID: "$(kli aid --name registrar --alias registrar)"
echo REGISTRAR OOBI: "$(kli oobi generate --name registrar --alias registrar --role witness)"

echo ADMIN AID: "$(kli aid --name admin --alias admin)"
echo ADMIN OOBI: "$(kli oobi generate --name admin --alias admin --role witness)"

kg guardian up --salt 0ACDEyMzQ1Njc4OWxtbm9GhI --config "${KERIGUARD_SCRIPT_DIR}/data/keriguard.yaml" --sentinel-config-path "${KERIGUARD_SCRIPT_DIR}/data/keriguard-sentinel.yaml"
kg guardian up --name peer --alias peer --salt 0ACDEyMzQ1Njc4OWxtbmPeer --config "${KERIGUARD_SCRIPT_DIR}/data/keriguard.yaml" --sentinel-config-path "${KERIGUARD_SCRIPT_DIR}/data/peer-keriguard-sentinel.yaml"

echo "Importing the KERIGuard Schema"
kli vc schema import --name registrar --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-interface-v1.0.0.json"
kli vc schema import --name registrar --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-connection-v1.0.0.json"
kli vc schema import --name registrar-sentinel --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-interface-v1.0.0.json"
kli vc schema import --name registrar-sentinel --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-connection-v1.0.0.json"
kli vc schema import --name admin --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-interface-v1.0.0.json"
kli vc schema import --name admin --schema "${KERIGUARD_SCHEMA_DIR}/wireguard-connection-v1.0.0.json"

kli vc registry incept --name admin --alias admin --registry-name admin

echo 'resolving keriguard'
kli oobi resolve --name admin --oobi-alias keriguard --oobi http://127.0.0.1:5642/oobi/EPf5v6oe7FuVImPgCo1ZvCDNpyz6pUZpsE1-GptErqqT/witness

echo 'resolving admin'
kli oobi resolve --name registrar --oobi-alias admin --oobi http://127.0.0.1:5642/oobi/EI6-tTwfonE2nKknuUkhkwRe-Op7kTYIeCUJcuuMUFUr/witness

echo 'resolving peer'
kli oobi resolve --name admin --oobi-alias peer --oobi http://127.0.0.1:5642/oobi/EIjg1HWuJEWMPsYxmrcZN5Lp4Ph5c6K_yBC3RF8JSXLd/witness

echo 'resolving registrar'
kli import --name registrar-sentinel --alias registrar --file /tmp/registrar.cesr
kli import --name admin --alias registrar --file /tmp/registrar.cesr

echo 'resolving sentinels'
kli import --name registrar --alias registrar-sentinel --file /tmp/registrar-sentinel.cesr
