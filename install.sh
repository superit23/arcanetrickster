#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
ln -s $DIR/arcane $VIRTUAL_ENV/lib/python3.10/site-packages/
python3 -m pip install -r $DIR/requirements.txt