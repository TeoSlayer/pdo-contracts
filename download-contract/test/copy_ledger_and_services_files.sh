SERVICE_HOST=$(hostname -A | cut -d' ' -f1)
mkdir -p $PDO_LEDGER_KEY_ROOT
cp $PDO_CONTRACTS_ROOT/docker/xfer/ccf/keys/networkcert.pem $PDO_LEDGER_KEY_ROOT
mkdir -p $PDO_HOME/etc/sites
cp $PDO_CONTRACTS_ROOT/docker/xfer/services/etc/site.toml $PDO_HOME/etc/sites/${SERVICE_HOST}.toml

