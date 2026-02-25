#!/bin/bash
# gcode-watcher.sh - Watch for new .gcode files and auto-convert to .3w
# Uses inotifywait + gcode_to_3w.py
#
# Install: sudo apt install inotify-tools python3-pycryptodome
# Or:      pip install pycryptodome 

WATCH_DIR="${1:-$HOME/cura_to_3w}"
CONVERTER="$(dirname "$(readlink -f "$0")")/gcode_to_3w.py"
DELETE_GCODE=false  # set to true to auto-delete .gcode after conversion

echo "Watching: $WATCH_DIR"
echo "Converter: $CONVERTER"
echo "Waiting for .gcode files..."

# Create watch dir if it doesn't exist
mkdir -p "$WATCH_DIR"

inotifywait -m -e close_write -e moved_to --format '%w%f' "$WATCH_DIR" | while read FILEPATH; do
    # Only process .gcode files
    [[ "$FILEPATH" != *.gcode ]] && continue

    echo ""
    echo "New file detected: $(basename "$FILEPATH")"

    # Wait briefly for file to stabilize (large files)
    sleep 1
    PREV_SIZE=0
    CURR_SIZE=$(stat -c%s "$FILEPATH" 2>/dev/null || echo 0)
    while [ "$CURR_SIZE" != "$PREV_SIZE" ]; do
        PREV_SIZE=$CURR_SIZE
        sleep 1
        CURR_SIZE=$(stat -c%s "$FILEPATH" 2>/dev/null || echo 0)
    done

    # Convert
    OUTFILE="${FILEPATH%.gcode}.3w"
    echo "Converting to: $(basename "$OUTFILE")"

    if python3 "$CONVERTER" "$FILEPATH" "$OUTFILE"; then
        echo "Success: $(basename "$OUTFILE") ($(stat -c%s "$OUTFILE") bytes)"

        if [ "$DELETE_GCODE" = true ]; then
            rm "$FILEPATH"
            echo "Deleted: $(basename "$FILEPATH")"
        fi

        # Optional: desktop notification
        if command -v notify-send &>/dev/null; then
            notify-send "3W Converter" "$(basename "$OUTFILE") ready!" --icon=printer
        fi
    else
        echo "Conversion failed!"
    fi
done