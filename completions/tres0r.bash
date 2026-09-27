# bash-Vervollständigung für tres0r – erzeugt von tres0r.docgen, nicht von Hand ändern
_tres0r() {
    local cur="${COMP_WORDS[COMP_CWORD]}" prev="${COMP_WORDS[COMP_CWORD-1]}"
    local cmd="" sub="" i word opts="" values="" choices="" positional=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        word="${COMP_WORDS[i]}"
        [[ $word == -* ]] && continue
        if [[ -z $cmd ]]; then cmd="$word"
        elif [[ -z $sub && -n ${_TRES0R_NESTED[$cmd]} ]]; then sub="$word"; fi
    done
    if [[ -z $cmd ]]; then
        COMPREPLY=($(compgen -W "pack unpack verify list info passwd diff append repair mount umount upgrade salvage encrypt decrypt keygen gui tui completion manpage fido2 keyfile pubkey protect keys genpass checkpass bench --help --version" -- "$cur")); return
    fi
    if [[ -n ${_TRES0R_NESTED[$cmd]} && -z $sub ]]; then
        COMPREPLY=($(compgen -W "${_TRES0R_NESTED[$cmd]}" -- "$cur")); return
    fi
    case "$cmd${sub:+ $sub}" in
        "pack")
            opts="--json -g --generate --password-file --offline -y --yes -r --recipient -R --recipients-file --recovery --no-password --sign --keyfile --fido2 --shares --shares-dir --key-passphrase-file -w --words -n --length --wordlist --sep --capitalize --digit --no-symbols --no-ambiguous -o --output -l --level --kdf-time -f --force -x --exclude --exclude-from --exclude-junk --no-ignore-file --strict-names -z --compress --no-pad --verify --no-space-check --split --threads --no-times --xattrs --acls --help"; values="-g|--generate|--password-file|-r|--recipient|-R|--recipients-file|--sign|--keyfile|--shares|--shares-dir|--key-passphrase-file|-w|--words|-n|--length|--wordlist|--sep|-o|--output|-l|--level|--kdf-time|-x|--exclude|--exclude-from|--split|--threads"
            [[ $prev == @(-g|--generate) ]] && choices="passphrase passwort"
            [[ $prev == @(--wordlist) ]] && choices="en de"
            [[ $prev == @(-l|--level) ]] && choices="schnell normal stark auto"
            ;;
        "unpack")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file --signer --signers-file -o --output --only --rename --no-space-check --xattrs --acls --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|--signer|--signers-file|-o|--output|--only"
            ;;
        "verify")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file --signer --signers-file --threads --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|--signer|--signers-file|--threads"
            ;;
        "list")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file"
            ;;
        "info")
            opts="--json --help"; values=""
            ;;
        "passwd")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file -g --generate --new-password-file --offline -y --yes -w --words -n --length --wordlist --sep --capitalize --digit --no-symbols --no-ambiguous -l --level --kdf-time --no-space-check --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|-g|--generate|--new-password-file|-w|--words|-n|--length|--wordlist|--sep|-l|--level|--kdf-time"
            [[ $prev == @(-g|--generate) ]] && choices="passphrase passwort"
            [[ $prev == @(--wordlist) ]] && choices="en de"
            [[ $prev == @(-l|--level) ]] && choices="schnell normal stark auto"
            ;;
        "diff")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file --quick --times --threads -x --exclude --exclude-from --exclude-junk --no-ignore-file --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|--threads|-x|--exclude|--exclude-from"
            ;;
        "append")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file -z --compress --sign --no-pad --no-space-check --strict-names --threads -x --exclude --exclude-from --exclude-junk --no-ignore-file --no-times --xattrs --acls --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|--sign|--threads|-x|--exclude|--exclude-from"
            ;;
        "repair")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file"
            ;;
        "mount")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file --signer --signers-file --verify --allow-other --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|--signer|--signers-file"
            ;;
        "umount")
            opts="--json --help"; values=""
            ;;
        "upgrade")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file -o --output -z --compress --no-pad --no-space-check --split --threads --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|-o|--output|--split|--threads"
            ;;
        "salvage")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file -o --output --rename --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|-o|--output"
            ;;
        "encrypt")
            opts="--json -g --generate --password-file --offline -y --yes -r --recipient -R --recipients-file --recovery --no-password --sign --keyfile --fido2 --shares --shares-dir --key-passphrase-file -w --words -n --length --wordlist --sep --capitalize --digit --no-symbols --no-ambiguous -o --output -l --level --kdf-time -z --compress --no-pad -f --force --split --threads --help"; values="-g|--generate|--password-file|-r|--recipient|-R|--recipients-file|--sign|--keyfile|--shares|--shares-dir|--key-passphrase-file|-w|--words|-n|--length|--wordlist|--sep|-o|--output|-l|--level|--kdf-time|--split|--threads"
            [[ $prev == @(-g|--generate) ]] && choices="passphrase passwort"
            [[ $prev == @(--wordlist) ]] && choices="en de"
            [[ $prev == @(-l|--level) ]] && choices="schnell normal stark auto"
            ;;
        "decrypt")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file --signer --signers-file -o --output -f --force --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|--signer|--signers-file|-o|--output"
            ;;
        "keygen")
            opts="--json -g --generate --passphrase-file --offline -y --yes -w --words -n --length --wordlist --sep --capitalize --digit --no-symbols --no-ambiguous -o --output --sign --unprotected -l --level --kdf-time --help"; values="-g|--generate|--passphrase-file|-w|--words|-n|--length|--wordlist|--sep|-o|--output|-l|--level|--kdf-time"
            [[ $prev == @(-g|--generate) ]] && choices="passphrase passwort"
            [[ $prev == @(--wordlist) ]] && choices="en de"
            [[ $prev == @(-l|--level) ]] && choices="schnell normal stark auto"
            ;;
        "gui")
            opts="--json --help"; values=""
            ;;
        "tui")
            opts="--json --help"; values=""
            ;;
        "completion")
            opts="--json --help"; values=""
            positional="bash zsh"
            ;;
        "manpage")
            opts="--json --help"; values=""
            ;;
        "fido2")
            opts="--json --help"; values=""
            ;;
        "keyfile")
            opts="--json -o --output --help"; values="-o|--output"
            ;;
        "pubkey")
            opts="--json --key-passphrase-file --help"; values="--key-passphrase-file"
            ;;
        "protect")
            opts="--json -g --generate --passphrase-file --offline -y --yes -w --words -n --length --wordlist --sep --capitalize --digit --no-symbols --no-ambiguous -l --level --kdf-time --help"; values="-g|--generate|--passphrase-file|-w|--words|-n|--length|--wordlist|--sep|-l|--level|--kdf-time"
            [[ $prev == @(-g|--generate) ]] && choices="passphrase passwort"
            [[ $prev == @(--wordlist) ]] && choices="en de"
            [[ $prev == @(-l|--level) ]] && choices="schnell normal stark auto"
            ;;
        "keys list")
            opts="--json --help"; values=""
            ;;
        "keys add-password")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file -g --generate --new-password-file --offline -y --yes -w --words -n --length --wordlist --sep --capitalize --digit --no-symbols --no-ambiguous --new-keyfile --new-fido2 -l --level --kdf-time --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|-g|--generate|--new-password-file|-w|--words|-n|--length|--wordlist|--sep|--new-keyfile|-l|--level|--kdf-time"
            [[ $prev == @(-g|--generate) ]] && choices="passphrase passwort"
            [[ $prev == @(--wordlist) ]] && choices="en de"
            [[ $prev == @(-l|--level) ]] && choices="schnell normal stark auto"
            ;;
        "keys add-shares")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file --shares-dir -y --yes --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|--shares-dir"
            ;;
        "keys add-recovery")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file -w --words -n --length --wordlist --sep --capitalize --digit --no-symbols --no-ambiguous -y --yes --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|-w|--words|-n|--length|--wordlist|--sep"
            [[ $prev == @(--wordlist) ]] && choices="en de"
            ;;
        "keys add-recipient")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file -r --recipient -R --recipients-file --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file|-r|--recipient|-R|--recipients-file"
            ;;
        "keys remove")
            opts="--json --password-file -i --identity --key-passphrase-file --keyfile --fido2 --share --shares-file --help"; values="--password-file|-i|--identity|--key-passphrase-file|--keyfile|--share|--shares-file"
            ;;
        "genpass")
            opts="--json -w --words -n --length --wordlist --sep --capitalize --digit --no-symbols --no-ambiguous -c --count --help"; values="-w|--words|-n|--length|--wordlist|--sep|-c|--count"
            positional="passphrase passwort"
            [[ $prev == @(--wordlist) ]] && choices="en de"
            ;;
        "checkpass")
            opts="--json --password-file --offline --help"; values="--password-file"
            ;;
        "bench")
            opts="--json --kdf-time --throughput --dir --size --help"; values="--kdf-time|--dir|--size"
            ;;
    esac
    if [[ -n $choices ]]; then COMPREPLY=($(compgen -W "$choices" -- "$cur")); return; fi
    if [[ -n $values && $prev == @($values) ]]; then COMPREPLY=($(compgen -f -- "$cur")); return; fi
    if [[ $cur == -* ]]; then COMPREPLY=($(compgen -W "$opts" -- "$cur"))
    elif [[ -n $positional ]]; then COMPREPLY=($(compgen -W "$positional" -- "$cur"))
    else COMPREPLY=($(compgen -f -- "$cur")); fi
}
declare -gA _TRES0R_NESTED=([keys]="list add-password add-shares add-recovery add-recipient remove")
shopt -s extglob
complete -o filenames -o bashdefault -F _tres0r tres0r
