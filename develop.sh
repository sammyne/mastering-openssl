#!/bin/bash

#docker run -it --rm -v ${PWD}/3rd_party:/cpp/3rd_party openssl:1.1.1 bash
docker run -it --rm -v ${PWD}:/cpp/mastering-openssl --workdir=/cpp openssl:v0.0.1 bash