#! /bin/bash

config_dir=${XDG_CONFIG_HOME:-$HOME/.config}
results=$(mktemp --tmpdir autostart.XXXXXXXXXX)

for f in $config_dir/autostart/*.desktop; do
    grep -m 1 -e '^[[:blank:]]*Exec' $f | cut -d = -f 2
    grep -m 1 -e '^[[:blank:]]*Name' $f | cut -d = -f 2
    grep -m 1 -e '^[[:blank:]]*Comment' $f | cut -d = -f 2
done | yad --width=500 --height=300 --title="Autostart editor" --image="gtk-execute" \
           --text="Add/remove autostart items" --list --editable --print-all \
           --multiple --column="Command" --column="Name" --column="Description" > $results

if [[ ${PIPESTATUS[1]} -eq 0 ]]; then
    rm -f $config_dir/autostart/*.desktop
    i=0
    cat $results | while read line; do
        eval $(echo $line | awk -F'|' '{printf "export NAME=\"%s\" COMMENT=\"%s\" COMMAND=\"%s\"", $2, $3, $1}')
        cat > $config_dir/autostart/$i$NAME.desktop << EOF
[Desktop Entry]
Encoding=UTF-8
Name=$NAME
Comment=$COMMENT
Exec=$COMMAND
Startuptify=true
Terminal=false
EOF
    $((i++))
    done
    unset NAME COMMENT COMMAND
fi

rm -f $results
exit 0
