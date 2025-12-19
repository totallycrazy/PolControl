#!/bin/bash
sudo apt install -y pkg-config python3-dev libgirepository-2.0-dev libglib2.0-dev libcairo2-dev gir1.2-gtk-3.0 git
cd ~ && git clone https://github.com/totallycrazy/PolControl.git && cd PolControl
python3 -m venv .venv && source ./.venv/bin/activate
pip3 install PyGObject
sudo cp -v helper.py /usr/local/bin/polkit-editor-helper 
sudo chown -v root:root /usr/local/bin/polkit-editor-helper
sudo chmod -v 755 /usr/local/bin/polkit-editor-helper
sudo cp -v org.example.polkit-editor.policy /usr/share/polkit-1/actions/
