#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
PYVERS="$(python3 --version | awk '{print $2}' | cut -d '.' -f 1,2)"
ln -s $DIR/arcane $VIRTUAL_ENV/lib/python$PYVERS/site-packages/
python3 -m pip install -r $DIR/requirements.txt
