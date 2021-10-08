# tower-attack-cache

This is a simple server that listens for tower attacks in AO, then requests the [Tower API](https://tower-api.jkbff.com/api/towers) to find out which tower fields are owned by this org and then sets all their fields as hot.

Any HTTP requests made to the server will return a JSON array of hot tower fields from attacks.

## Configuration

Done via enviroment variables.

`USERNAME`, `PASSWORD` and `CHARACTER` are required and will set the credentials for the bot, `HOST` defaults to `0.0.0.0` and `PORT` defaults to `7880`.

To enable logging, set `RUST_LOG` to a value like `info`, `debug` or `trace`.
