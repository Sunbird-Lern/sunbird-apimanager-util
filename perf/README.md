### AB was used to benchmark the APIs

As there is no state involved in the APIs, we can use the same payload for a quick benchmark.

The payload is saved in the json files that are in this folder.

To test the v1/sign/payload endpoint with a concurrency of 300 and each thread making 100 request
ab -r -k -c 300 -n 30000 -T 'application/json' -p sign.json  http://localhost:4000/v1/sign/payload

To test the v2/mobile_device/register endpoint with a concurrency of 300 and each thread making 100 request
ab -r -k -c 300 -n 30000 -T 'application/json' -p register.json  http://localhost:4000/v2/consumer/mobile_device/credential/register