#!/bin/bash
#export VAULT_ADDR="https://vault-hc-msa.vault.3d959afc-d0d4-4a35-bcec-4fc220acda48.aws.hashicorp.cloud:8200"
#export VAULT_NAMESPACE="admin"
#export VAULT_TOKEN=
#export VAULT_SKIP_VERIFY=true

#root@vault-0:/etc/vault.d# vault operator init
#Unseal Key 1: a2uU26c6MpmrD6JRORtz5bPmURc6lFxOAPquOsSjam2y
#Unseal Key 2: jyvdkYi3Y2fQkiJ9v5SSimgQM2toRXeKfPwCKmZC/o/e
#Unseal Key 3: dC1LveLnYe9wS3OiX4ple0vEzsZlpLSvTzhFXUbGvpaZ
#Unseal Key 4: yfPPk7oWZvBk2Pgj4OfuTLOAgInjq/tO+boxBelrlHg/
#Unseal Key 5: bGyeRhM2pNjHG+yTdFOZ+cicyJ9aVELEEndGQumt+Nvt
#
#Initial Root Token: s.OQMSO1NC4aegbQHVI2reN7lj
#
#Vault initialized with 5 key shares and a key threshold of 3. Please securely
#distribute the key shares printed above. When the Vault is re-sealed,
#restarted, or stopped, you must supply at least 3 of these keys to unseal it
#before it can start servicing requests.
#
#Vault does not store the generated master key. Without at least 3 keys to
#reconstruct the master key, Vault will remain permanently sealed!
#
#It is possible to generate new unseal keys, provided you have a quorum of
#existing unseal keys shares. See "vault operator rekey" for more information.
export VAULT_SKIP_VERIFY=true

help()
{
    echo ""
    echo "Usage: $0 -a VAULT_ADDR -n VAULT_NAMESPACE -t VAULT_TOKEN"
    echo -e "\t-a Informe o endereço do Vault"
    echo -e "\t-n Informe o namespace do Vault"
    echo -e "\t-t Informe o token do Vault"
    echo -e "\t-p Informe o path do Vault"
    echo -e "\t-r Informe o nome da role"
    exit 1
}

create_keys()
{
    while [ ! -e $HOME/.ssh/id_rsa.pub ] && [ ! -e $HOME/.ssh/id_rsa ]
    do
        ssh-keygen -q -P "" -f $HOME/.ssh/id_rsa
        $LOG "criando chave privada e publica"

    done
}

enable_secret()
{
    #VAULT_SECRET_SSH=`secrets list -format=yaml | grep "type: ssh" | sort -u | cut -d" " -f 4`
    $VAULT secrets enable -path=$VAULT_PATH ssh
    RC=$?
    if [ $RC = "0" ]; then
        $LOG "ativando o secret ssh..."
    else
        $LOG "secret já ativo para o path $VAULT_PATH..."
    fi
}

generate_signing_key()
{
    PUBLIC_KEY=`$VAULT read -field=public_key $VAULT_PATH/config/ca`
    RC=$?
    if [ $RC = "0" ]; then
        $LOG "baixando a chave publica..."
        echo $PUBLIC_KEY > $HOME/.ssh/trusted-$VAULT_ROLE-user-ca-keys.pem
        chmod 644 $HOME/.ssh/trusted-$VAULT_ROLE-user-ca-keys.pem
    else
        $LOG "gerando e baixando a chave publica..."
        $VAULT write $VAULT_PATH/config/ca generate_signing_key=true
        $VAULT read -field=public_key $VAULT_PATH/config/ca > $HOME/.ssh/trusted-$VAULT_ROLE-user-ca-keys.pem
        chmod 644 $HOME/.ssh/trusted-$VAULT_ROLE-user-ca-keys.pem
    fi
}

create_role()
{
    $VAULT write $VAULT_PATH/roles/$VAULT_ROLE -<<"EOH"
{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "allowed_extensions": "permit-pty,permit-port-forwarding",
  "default_extensions": [
    {
      "permit-pty": ""
    }
  ],
  "key_type": "ca",
  "max_ttl": "12h",
    "ttl": "12h"
}
EOH

    RC= $?
    if [ $RC = 0 ]; then
        $LOG "role criada com sucesso..."
    else
        $LOG "problema na criação da role..."
    fi
}

update_system()
{
    apt update
    apt upgrade -y
    apt install -y jq
}

install_vault()
{
    $CURL $VAULT_REPO/gpg | apt-key add -
    apt-add-repository "deb [arch=amd64] $VAULT_REPO $(lsb_release -cs) main"
    apt update
    apt install -y vault
}

enable_vault()
{
    systemctl enable vault
    systemctl start vault
}

init_vault()
{
    resp=`vault operator init -format=json`
    for i in $(seq 3)
    do 
        vault operator unseal $(echo $resp | jq -r .unseal_keys_b64[$i])
    done
}

CURL="curl -fsSL"
VAULT_REPO="https://apt.releases.hashicorp.com"
VAULT=`which vault`
LOGGER=`which logger`

if [ -z $LOGGER ]; then
    LOG="echo"
else
    LOG="$LOGGER -tag VAULT_SETUP"
fi

update_system
install_vault
enable_vault
init_vault

vault login $(echo $resp | jq -r .root_token)

if [ -z $VAULT ]; then
    $LOG "vault não instalado..."
    exit 0 
fi

while getopts a:n:t:p:r: flag
do
    case "${flag}" in
        a) VAULT_ADDR=${OPTARG};;
        n) VAULT_NAMESPACE=${OPTARG};;
        t) VAULT_TOKEN=${OPTARG};;
        p) VAULT_PATH=${OPTARG};;
        r) VAULT_ROLE=${OPTARG};;
        ?) help;;
    esac
done

if [ -z "$VAULT_ADDR" ] || [ -z "$VAULT_NAMESPACE" ] || [ -z "$VAULT_TOKEN" ]
then
    echo "Informe todos os parâmetros..."
    help
fi

export VAULT_ADDR=$VAULT_ADDR
export VAULT_NAMESPACE=$VAULT_NAMESPACE
export VAULT_TOKEN=$VAULT_TOKEN

while [ ! -e $HOME/.ssh/id_rsa.pub ]
do
    if [ -e $HOME/.ssh/id_rsa ]; then
        $LOG "gerando a chave publica a partir da chave privada já existente..."
        ssh-keygen -y -f $HOME/.ssh/id_rsa > $HOME/.ssh/id_rsa.pub
        chmod 644 $HOME/.ssh/id_rsa.pub
    else
        $LOG "criando par de chaves.."
        create_keys
    fi
done

if [ -e $VAULT ]
then
    enable_secret
    generate_signing_key
    create_role
    vault write $VAULT_PATH/sign/$VAULT_ROLE public_key=@$HOME/.ssh/id_rsa.pub
    vault write -field=signed_key $VAULT_PATH/sign/$VAULT_ROLE public_key=@$HOME/.ssh/id_rsa.pub > $HOME/.ssh/bastionhost-cert.pub
    vault write -field=signed_key $VAULT_PATH/sign/$VAULT_ROLE public_key=@$HOME/.ssh/id_rsa.pub valid_principals="bastionusr" > $HOME/.ssh/bastionusr.cert
fi