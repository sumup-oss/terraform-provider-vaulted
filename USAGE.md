# Usage

## Prerequisites

The following apply here as well.

https://github.com/sumup-oss/vaulted#prerequisites

## Provider

Specify in a terraform module (e.g `main.tf`)

```hcl
provider "vaulted" {
  address = "http://example.com:8200"
  token = "myverysecrettoken"
  skip_tls_verify = true
  
  client_auth = {
    cert_file = "./vault.crt"
    key_file = "./vault.key"
  }
  
  private_key_path = "./privkey.pem"
}
```

## New resource

Create a new resource using [vaulted terraform new-resource]. E.g

```shell
> cat secret.raw
{
  "value": "verysecret"
}

> vaulted terraform new-resource \
--public-key-path ./public.pem \
--resource-name myapp_database \
--path secret/myapp/database \
--in secret.raw 
Terraform HCL below:
"resource" "vaulted_vault_secret" "myapp_database" {
"path" = "secret/myapp/database"

"payload_json" = "$VED;1.0::vEaUcniuwR+kK9i9KR8pKADLRf2mvIJzLcYXrQTYH8O5YsFzZI8yf7oJl7GDBX7qUTWjMh3DfC+xrSGso8JcNg5w7FEwLdV5kU6Oz75B27bUZmWIjolZ2FYGl/gzE3zriHJVdSTbDhs4hhUGrtjgZtOhA5v0gZwO2WrhGMsZgHBxkOjinsui3pLfE2R7Yf9mlxUiLWlbccV07xWpTFk2Hr9TpKmPyF+1clXrVGNbOM8xzMBKE4NLZb1Xpq0sE1a3hCl2QopNm1y+kQAQq8tGOUKEkhXpXUSLkeeNXQNRs4V1EZe3ubgyGzdSJRIw0xhqx5/wqgHGh/Fzl29QPmzYosZqoLv4kimCSZ3T/3wQktjnlIayIB3VCtLNwe8Cz1QiECpw36s/tMPzCf4w141AF//DFXsbTpILLDj/20f+tMclNdy5GNBBD9XMhlum+bwU+CUj515Kp56kTF6d8gAjFDHWr+eQa3MUJHUgmTZmMe8cgOlru5nDw5PHxnseRmRgYo1Xz9qP7jlTCPjlw0QgLdIZLXz1/xahpErt6leNwQhiMEBuDGM49juplD9GQSQW4LzYls7fcfMdX3jbLXYJMrOStT7AX6VOH4G2/r2tbxzbSm6Vq0efwjf5oLfLqpopibd5BqUgOrOrhSxHMvn48tsWxkt3atLgDwszF8acz8w=::qe+6yDNFEZZSr8szYxrganvpmaNS41lk7hO88EHKjGGDbhsJMaou2x525KyV01gcl7Dz2S/4tPk="
}
```

Or you can directly append the resource to an existing file using [vaulted terraform new-resource]. E.g

```shell
> cat existing.tf
"resource" "vaulted_vault_secret" "new_tf_myapp_database" {
  "path" = "secret/myapp/database"

  "payload_json" = "$VED;1.0::Iylm3sqk5+OwTwG6IjFUABoarfsYpSXLyXJ2sDRq/2Ao/VMbUdBrgp0ZbRpwWiOonjTS+1CYyaoDZg4qc7Bvpb4mQk34FY2znTxffLpNLrWnFxXN+6AEkViC1EbYiWe3lD6e8BMRrVOAqI1sXYJ+j0JzOel2gJ5Vxi/9T5rbReUyKyASoXVcQwi07GeMnYMRIoer/hdavzW+XxPurmUnwK5XbJiQCdZtox3/vIqMJpW6jVZitgxLr8WdOb0uBrUKw3MV9hvgurf5rlAjTbicTIaZH8nN3bCwol/ydrvKBtMda3Gsr8vT0oqgbT/+AI+XXhI0iXiSJJ7JY0ISbXvucF9PIicC89oc4ybq5BCmyIX6MqaUe4QpCcYP4l0/vJRSrvJmht8QVCNNitBcHiiD/lItyTAo6NE7PNW+W/huY2yj1oZb78H9TEU6JCppcbiQK6TEt8w1Ab7DvXN817oD75Umt8wVl3VvsJNkeiO2Qbk2T2yxkqh7dOo89pgbebGaM0cerf+Nax9VOP/rC05/KkJCqdkrVYT/3kRkPBZuBYri6v0nhoDzJDMcGmNXaj79xxT1Y2D7Ur8wQ2XiyHITQ3KkQajLwD2Dip6/NiTuhN1mAUaO6la0EkTy+bOzmHbhXrJVTBXUl1m7MDNFOgYWUduPk+shGQ1NFX1bok/vQ2E=::e0V8lvdyVzga4X6LV6LWINnhp4+S3cM2Mr5ZMgf7jLhJ3le0RyMXhRu4Qj36nuEPrw+TlLw6Ttg="
}


> cat secret.raw
{
  "token": "verysecret"
}

> vaulted terraform new-resource \
--public-key-path ./public.pem \
--resource-name myapp_proxy \
--path secret/myapp/proxy \
--in secret.raw \
--out existing.tf 

> cat existing.tf

"resource" "vaulted_vault_secret" "new_tf_myapp_database" {
  "path" = "secret/myapp/database"

  "payload_json" = "$VED;1.0::Iylm3sqk5+OwTwG6IjFUABoarfsYpSXLyXJ2sDRq/2Ao/VMbUdBrgp0ZbRpwWiOonjTS+1CYyaoDZg4qc7Bvpb4mQk34FY2znTxffLpNLrWnFxXN+6AEkViC1EbYiWe3lD6e8BMRrVOAqI1sXYJ+j0JzOel2gJ5Vxi/9T5rbReUyKyASoXVcQwi07GeMnYMRIoer/hdavzW+XxPurmUnwK5XbJiQCdZtox3/vIqMJpW6jVZitgxLr8WdOb0uBrUKw3MV9hvgurf5rlAjTbicTIaZH8nN3bCwol/ydrvKBtMda3Gsr8vT0oqgbT/+AI+XXhI0iXiSJJ7JY0ISbXvucF9PIicC89oc4ybq5BCmyIX6MqaUe4QpCcYP4l0/vJRSrvJmht8QVCNNitBcHiiD/lItyTAo6NE7PNW+W/huY2yj1oZb78H9TEU6JCppcbiQK6TEt8w1Ab7DvXN817oD75Umt8wVl3VvsJNkeiO2Qbk2T2yxkqh7dOo89pgbebGaM0cerf+Nax9VOP/rC05/KkJCqdkrVYT/3kRkPBZuBYri6v0nhoDzJDMcGmNXaj79xxT1Y2D7Ur8wQ2XiyHITQ3KkQajLwD2Dip6/NiTuhN1mAUaO6la0EkTy+bOzmHbhXrJVTBXUl1m7MDNFOgYWUduPk+shGQ1NFX1bok/vQ2E=::e0V8lvdyVzga4X6LV6LWINnhp4+S3cM2Mr5ZMgf7jLhJ3le0RyMXhRu4Qj36nuEPrw+TlLw6Ttg="
}
"resource" "vaulted_vault_secret" "existing_tf_myapp_proxy" {
  "path" = "secret/myapp/proxy"

  "payload_json" = "$VED;1.0::yEGEXwx1KdffiJNCJBk98Qfhat5RfYRF9rcBeaJwrl7uRGBRhaZQdKS+Oh9Sfy+mZgqdIbHMaT9Xuu+L8HfXNnz0bJoyJzEVsXGMtqpxL1iRcbBgDBnHQJtvR5+/YMmwXkYJ/vK+3WwJPPYkFxc90RrimsW4ZR724ar/x2OHoVq7TdJ1YaYBKJnpzMZb1TSKFTpiZE292b9FAgjRjdpYMRscGoimfrR+xgwYlpxl84YUusIBHEzd0KFq5IYJ4ssTXGNV1bXGnYPq9CiwAkq5gPM/oNHrUGXu6Dxz07JOO9o+sULj2j5lsFLPXxEuNDXisGzrX/6WS7IA/+kmy4S68N/9MpvnGDtJheZzSNnJ//l7YE5Q8WsFNiLLH3VKTMADQoK0YUiGPe2v7R5x3/izB+fsDAgtCRwHNMve9gu2lCVxdXUeVewZvjW76TUhYh8H/NeRSw3r/2CpYrW7igppJTVJSddb6ynYMmRniYdD1vKy5+PRRmnwqNLkzdWeQ5qBe2zCJjha0p0IDdK8+Yx/tYIFHEBZXHVPXXlrXtPjdlKDELBmgTWiSV4jNHDpZgZkKTCHznqlcAWK1lsoMciMHSMa57SIe2oUrNdqzSrlA4xbrx6+Y486hImOLvnx3ej//XQNfoMBtUXpErSsXnlj0k76o708OcR+qBDWK81N7T0=::Oi/p5Ea7k4R6sBTO3ylKAGX7HSTSfedYso0+bJLflcKO0Lfk+SCpufXCIG8If3HOmxj2grENSew="
}
```

## Migrating existing code base

Looking to migrate terraform modules using `vault_encrypted_secret` resources?

Migrate them using [vaulted terraform migrate].

```shell
> cat existing.tf 
"resource" "vault_encrypted_secret" "vault_encrypted_secret_myapp_database_password" {
  "encrypted_data_json" = "YR1qQ9Ui0olLpcyoosHJ552a740JZiL2xvyEEgytGyJAfL4zKNj5KT4Eeov0t05g"

  "encrypted_passphrase" = "3fmxsEMnVCSR0ks7oTr4xE70kTcfD8xGbWHWTLJEdYkoq02SOcmnQKu7KXpirGNrLHrI97GdBl2jjGKgsAdTzPpiGjbr9r/94pkZevbKqjYHIBBWXjbMPXgSPL/jTb1K9JqrEyC+HUeh5GEZ9ZtN0kKuJNlfVZ4h5ZFHVcJ1Cp81OxNMPhNnn0YLqZ5D5oRSPSnOwbqWEVcQ1Sq4ycmdfwB1VrcsqPZZoVqMsmwkAdHFvjt6O2JTpFxBeIXlE5+ImUywONAItM66CY0dVbG0Zra+Tp6zhwqQSSBe8ufDBA8RCkTdG0/vuSDd1uiQqskK7Bov4c8cgJYWSDw+STCG3etQ+7ezXlGxQacQC4xzYSqT+fAvapoWwX5j9tjV+krhUQhNnN7fJaKYFTFmrMwl4JOyhjUqrRCXrYw5Et+iKJlRUSA0OVZu1cpaSBtPfpEemVdfH2GXopnf4lhtVLuCKJ2dOecETfEpOli+Ejv/QQ3LltfKdZZuXC4CnIOiyFxDTW/nOCVErzVCh1kofWjiF+9mQPB7lx1naTllKark4sjLrzCo8Nqdj2ScbceGwMnprKGHPisX7PVHMjZ5Gfe617HUsvSm+2tKEGnG9bB+5lOYeftrEJX8WgD44RvNs2Q4A5w049ZyRrUwWC0OXhX/ejjb292VHgrf8P1wxIKwKOA="

  "path" = "secret/myapp/database_password"
}

> vaulted terraform migrate \
--private-key-path ./private.pem \
--public-key-path ./public.pem \
--in existing.tf  

Terraform HCL below:
"resource" "vaulted_vault_secret" "vault_encrypted_secret_myapp_database_password" {
  "path" = "secret/myapp/database_password"

  "payload_json" = "$VED;1.0::tsTHr4e2by2w7Q95IF4U9p5YQxx5FHRV1xhlk1qC9aQfAJO+PUaL4jierwUx0/PiwbmDmRS6BW94cJgt2jfq5+mfmuRR7L5KX5+6eylqCF39RkCjpWOb7ayNHOq7o1enKVLiW6SCYTVoAFhYqrw44wHdU9oU7pivbTu1TisXt6/+Ev8FYTf45d4A/gzu+Z/zsPONXjLvBMHX7ozKtHEudx7E4IRvv4NoZUTinSPwnrHOc4p09+LRRegSKkRPSD1q4dJyRuPYEQqC0j1UArqUookFQN8fMZLLyhFphsIcEW19Xn6SDQJBDi6gPSSe26tuWLRQroAL77Wa/Ira2GX7DKRfPU8Ly3WrqlM4jfObcnxpi1Vgo/vUdtpnYP2kHCHCuUKd8H+1uApyVVFyN821Qpn6uMBR2DsjxEX95N92BrVHZusakm1bp6Ys5m+/k5ZCB95RSr6eDpKI3+xIbjNKusa2m/YE55QUGMo5ajabZIdalGQPoXnENmAHvcAzhtPDTpd30T3jR4O5rqqPt2jmD2K0SxYKYgC+PFCnTHe0Gb6hLTE7cylGQNpRlUCp4h92jk4fIu/6dItWnHvauLo8yn1QG2ooEazq1KnDimTBeplFMwAWwZhWWhqc5DilG7e8TfrUMtylWGHDhZWwviJhyjZwY353Lu68IkcknPw3vQM=::O9l40wFoOfx4fiS1DQlrF7+lxYGSskyZna8U4rrr/ngQEL3PWNEtB4M7PgX1jWR0"
```

## Rotating secrets

The rotation process is explained in https://github.com/sumup-oss/vaulted/blob/master/HOW_IT_WORKS.md#rotate-secret-flow .

Using [vaulted terraform rotate] we can do it like:

```shell
> cat existing.tf
"resource" "vaulted_vault_secret" "existing_tf_myapp_proxy" {
  "path" = "secret/myapp/proxy"

  "payload_json" = "$VED;1.0::yEGEXwx1KdffiJNCJBk98Qfhat5RfYRF9rcBeaJwrl7uRGBRhaZQdKS+Oh9Sfy+mZgqdIbHMaT9Xuu+L8HfXNnz0bJoyJzEVsXGMtqpxL1iRcbBgDBnHQJtvR5+/YMmwXkYJ/vK+3WwJPPYkFxc90RrimsW4ZR724ar/x2OHoVq7TdJ1YaYBKJnpzMZb1TSKFTpiZE292b9FAgjRjdpYMRscGoimfrR+xgwYlpxl84YUusIBHEzd0KFq5IYJ4ssTXGNV1bXGnYPq9CiwAkq5gPM/oNHrUGXu6Dxz07JOO9o+sULj2j5lsFLPXxEuNDXisGzrX/6WS7IA/+kmy4S68N/9MpvnGDtJheZzSNnJ//l7YE5Q8WsFNiLLH3VKTMADQoK0YUiGPe2v7R5x3/izB+fsDAgtCRwHNMve9gu2lCVxdXUeVewZvjW76TUhYh8H/NeRSw3r/2CpYrW7igppJTVJSddb6ynYMmRniYdD1vKy5+PRRmnwqNLkzdWeQ5qBe2zCJjha0p0IDdK8+Yx/tYIFHEBZXHVPXXlrXtPjdlKDELBmgTWiSV4jNHDpZgZkKTCHznqlcAWK1lsoMciMHSMa57SIe2oUrNdqzSrlA4xbrx6+Y486hImOLvnx3ej//XQNfoMBtUXpErSsXnlj0k76o708OcR+qBDWK81N7T0=::Oi/p5Ea7k4R6sBTO3ylKAGX7HSTSfedYso0+bJLflcKO0Lfk+SCpufXCIG8If3HOmxj2grENSew="
}

> vaulted terraform rotate \
--public-key-path ./public.pem \
--private-key-path ./private.pem \
--in ./existing.tf \
--out ./rotated.tf  

> cat rotated.tf
"resource" "vaulted_vault_secret" "existing_tf_myapp_proxy" {
  "path" = "secret/myapp/proxy"

  "payload_json" = "$VED;1.0::X0gnmSPzHvbu/TFZxA8SsKaZNUHQellq0ers67xCFfT5ImlVoUTyC4MNjBPXK+rbEMxSB4iPNILVl4+fCGIh/pP9maJ7CSufEkPuDjFKtw5mc9h7X5bjMvypeU9AOzdiszm/Bm34mrA442+KSomzv4rV8mGl133aY+jLxPtAvTQmtlNkaVtd2Wlu3fggZoERkl9jAiWWkd6Tw73kSPShExwth7Y+oaARjICDPgRNMr2IgX6UYpeIOHXNac2Jb+zjfkGsSlzSoasYX4816sJPmlmLtP6uwJijw7UxMbUqp1GNul5wlHwtcNTNwcpupmwf9mD5UwgcJe30ljpm9rcPYDXYt0QaeGiVbBAQYyWMtElVS3ZS8Ikn1RCeW+AIW9/SRUjBEXkeuMU+MtTV/XOWwxBzM/GEfQNqfbnemh4sR5huGmyhz75qudFvJMDK4woSFZjqVRS+NB3IYw6wIXjWZ4ZalJlNEJtGnO2jgTw9I2W87RrqO5Iprh6usKwZzowk5MscEOsvcYc3EZXmxtOBdthUWLSd+EuU7bpFslZs3JCzf+aH34GzUWnhPaw3wfXJNbdEIt7YipNg6bwBbPPuFJ4JCeN36gVJ6bBbdoJLZUvdojJS+ZEYKxRs1/bzqGXReKKriH6zfZzLZD5ccQeg8fG+Yj+pbRK8avwADNwHZxc=::hKU9T2ZlQWhItCgmPhDUCSrBmxFeShTQxdMQ/FQ6Kak8upDLpoNAF+D+0CNu5e1XMTkHJqWEFCs="
}
```

**Note, it's checked during command execution whether your public and private keys are from the same pair. It fails if they are not.**

## Rekeying secrets

The rekey process is explained in https://github.com/sumup-oss/vaulted/blob/master/HOW_IT_WORKS.md#re-key-secret-flow .

Assuming that we already have generated a new keypair by following 
https://github.com/sumup-oss/vaulted#prerequisites, we can use [vaulted terraform rekey] like:

```shell
> cat existing.tf
"resource" "vaulted_vault_secret" "existing_tf_myapp_proxy" {
  "path" = "secret/myapp/proxy"

  "payload_json" = "$VED;1.0::yEGEXwx1KdffiJNCJBk98Qfhat5RfYRF9rcBeaJwrl7uRGBRhaZQdKS+Oh9Sfy+mZgqdIbHMaT9Xuu+L8HfXNnz0bJoyJzEVsXGMtqpxL1iRcbBgDBnHQJtvR5+/YMmwXkYJ/vK+3WwJPPYkFxc90RrimsW4ZR724ar/x2OHoVq7TdJ1YaYBKJnpzMZb1TSKFTpiZE292b9FAgjRjdpYMRscGoimfrR+xgwYlpxl84YUusIBHEzd0KFq5IYJ4ssTXGNV1bXGnYPq9CiwAkq5gPM/oNHrUGXu6Dxz07JOO9o+sULj2j5lsFLPXxEuNDXisGzrX/6WS7IA/+kmy4S68N/9MpvnGDtJheZzSNnJ//l7YE5Q8WsFNiLLH3VKTMADQoK0YUiGPe2v7R5x3/izB+fsDAgtCRwHNMve9gu2lCVxdXUeVewZvjW76TUhYh8H/NeRSw3r/2CpYrW7igppJTVJSddb6ynYMmRniYdD1vKy5+PRRmnwqNLkzdWeQ5qBe2zCJjha0p0IDdK8+Yx/tYIFHEBZXHVPXXlrXtPjdlKDELBmgTWiSV4jNHDpZgZkKTCHznqlcAWK1lsoMciMHSMa57SIe2oUrNdqzSrlA4xbrx6+Y486hImOLvnx3ej//XQNfoMBtUXpErSsXnlj0k76o708OcR+qBDWK81N7T0=::Oi/p5Ea7k4R6sBTO3ylKAGX7HSTSfedYso0+bJLflcKO0Lfk+SCpufXCIG8If3HOmxj2grENSew="
}

> vaulted terraform rekey \
--new-public-key-path ./new-public.pem \
--old-private-key-path ./old-private.pem \
--in ./existing.tf \
--out ./rekeyed.tf  

> cat rekeyed.tf

"resource" "vaulted_vault_secret" "existing_tf_myapp_proxy" {
  "path" = "secret/myapp/proxy"

  "payload_json" = "$VED;1.0::FxsgSqkqKeIx4FhEefiN9Hw76YTaI85qDWph3j0Thp+zjUfRYnsSHTgakZu/hUfDxfEp/u/F2X8/mXCFDcIaHz4IKSC8UC1ggkgwnGWBQLKdpfnswcJ2ag6SUMyA7OoLi6cNnlhrgUqxMksG8gPQ+VkngxISDhkX/jIWXb8iZbdeJN72L69qS8BeFNn1wfK2UY/VbudXz+dn2J+azDwmq+PNGddoqW9hpSksGllHzqFOhHerIeJwuumioNFRZIh9Wlb+CY+xS2b3pRj0ugu44MvlJXTH6l7X6mg9MsnDHN0rFFiK3WMNDatmVFErLZ9xXMjzagzJ31GJ1gb90hBje8rPyq91yL8tnHhwkUliWp6Wp2N4XHTNb6MjzUPiRY62DhUhu0+PRTgc2/FvoqEcy/sKu8afpC1Nh2Sj1IVK6pK0zdaVUPZ0skU+z8OIxAY+QCFWPHA/bnIqv8KrpAwgLYb5DHxd8RHIw9IBAbxYzbdt8ZFSYsDdmQ71hVwxdB+rKRQZU/nzBBZcs8fA2VWQuN6nyq/scFybliS8AM4Q/DMS3EF2/YTh3R42KJckBHJ7pr2/8BNmr44OGeH2iU7Rls+ISHygz/gB3vOA7Zl1sYQE1QDWzuJda8gSifVflgD/RFvNzJ1wJTeRxFQnGpTKuWrlmoNAWaIQQqJmA7kh8is=::wZ4HrB99KOkOifO2qKegGDfjq0gwsjhMcmdpiQsPVNhP+1XkFoYudBUnIdGeH/NumHSwc/Dq9Xk="
}
```

**Note, it's checked during command execution whether your public and private keys are from the same pair. It fails if they are.**

**Can also be written in new file or appended to existing one by specifying `out` flag**.

[vaulted terraform new-resource]: https://github.com/sumup-oss/vaulted/blob/master/COMMANDS.md#vaulted-terraform-new-resource
[vaulted terraform migrate]: https://github.com/sumup-oss/vaulted/blob/master/COMMANDS.md#vaulted-terraform-migrate
[vaulted terraform rotate]: https://github.com/sumup-oss/vaulted/blob/master/COMMANDS.md#vaulted-terraform-rotate
[vaulted terraform rekey]: https://github.com/sumup-oss/vaulted/blob/master/COMMANDS.md#vaulted-terraform-rekey
[vaulted]: https://github.com/sumup-oss/vaulted
