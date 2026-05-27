#!/bin/bash

sentinel watcher add --name keriguard --alias keriguard --watcher keriguard-sentinel --watched admin --oobi http://127.0.0.1:5642/oobi/EI6-tTwfonE2nKknuUkhkwRe-Op7kTYIeCUJcuuMUFUr/witness
sentinel watcher add --name registrar --alias registrar --watcher registrar-sentinel --watched admin --oobi http://127.0.0.1:5642/oobi/EI6-tTwfonE2nKknuUkhkwRe-Op7kTYIeCUJcuuMUFUr/witness