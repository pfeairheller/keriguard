#!/bin/bash


# Issue Interface credential to keriguard for main file
kg interface create --name admin --alias admin --registry-name admin --recipient keriguard --interface-name wg0 --listen-port 5000 --address "10.0.0.4/24" --interface-description "Main Interface Credential" --registrar-url http://localhost:8080/
kli vc list --name admin --alias admin --issued

# Issue Interface credential to peer
kg interface create --name admin --alias admin --registry-name admin --recipient peer --interface-name wg0 --listen-port 5000 --address "10.0.0.3/24" --interface-description "Main Interface Credential" --registrar-url http://localhost:8080/

kli vc list --name admin --alias admin --issued
kli status --name admin --alias admin
kg peers connect --name admin --alias admin --peer "name=keriguard,endpoint=147.182.240.249:43567,allowed-ips=10.0.0.4/32,environment=production" \
                                            --peer "name=peer,endpoint=143.56.178.5:43567,allowed-ips=10.0.0.3/32,environment=production" \
                                            --registrar-url http://localhost:8080/

kli vc list --name admin --alias admin --issued

kli status --name admin --alias admin
