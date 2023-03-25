#!/bin/bash
sudo docker run --name bbdev -p 5433:5432 \
                -e POSTGRES_PASSWORD=mysecretpassword \
                -d postgres
