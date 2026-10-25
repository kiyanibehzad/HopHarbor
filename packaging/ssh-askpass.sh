#!/bin/sh
# SSH invokes this with its prompt; the helper alone reads this app's Keychain item.
askpass_dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
exec "$askpass_dir/keychain-helper" askpass "$@"
