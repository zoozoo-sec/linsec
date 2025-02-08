#!/bin/bash
cd /root/new
validated_files=("/home/zoozoo/test")
analyse="/root/new/suspects/"
FIFO_FILE="/tmp/monitored_file"
if [[ ! -p "$FIFO_FILE" ]]; then 
    mkfifo $FIFO_FILE
    echo "[*] FIFO pipe created at /tmp"
fi

source /root/new/libraries/bin/activate

exec_script() {
    python /root/new/monitor.py > /root/new/logs/monitorpy 2>&1 
}

get_file(){
    echo "[*] Listening on fifo pip: $FIFO_FILE"
    while true; do
    filename=$(cat $FIFO_FILE)
    
    # Check if filename is empty
    if [[ -z "$filename" ]]; then
        echo "Error: Empty filename received."
        continue
    fi
    
    checked=0
    for files in "${validated_files[@]}"; do
        if [[ "$files" == "$filename" ]]; then
            checked=1
            break  # Exit loop early if found
        fi
    done

    if [[ $checked -eq 0 ]]; then
        mv "$filename" "$analyse"      
        ./ioctl A "$filename"
        ./ioctl A "$filename"

        python /root/new/static-analysis.py "$analyse/$(basename "$filename")" > /root/new/logs/staticpy 2>&1
        
        danger_level=$? 
        echo $danger_level

        if [[ $danger_level -eq 111 ]]; then
            echo "Malware Detected!"
            rm "$analyse/$(basename "$filename")"
            ./ioctl B "$filename"
            ./ioctl B "$filename"
        elif [[ $danger_level -eq 222 ]]; then
            echo "$filename seems benign..\n Proceeding with dynamic analysis."
            python /root/new/dynamic-analysis.py "$analyse/$(basename "$filename")" -x > /root/new/logs/dynamicpy 2>&1
            danger_level=$?
            echo $danger_level

            if [[ $danger_level -eq 111 ]]; then
                echo "Malware Detected!"
                rm "$analyse/$(basename "$filename")"
                ./ioctl C "$filename"
                ./ioctl C "$filename"
            elif [[ $danger_level -eq 222 ]]; then
                echo "$filename seems benign..\n"
                validated_files+=("$filename")
                mv "$analyse/$(basename "$filename")" "$filename"
                ./ioctl D "$filename"
                ./ioctl D "$filename"
            fi
        fi
    else
        echo "Already Validated: $filename"
    fi

    # Create directory only if it does not exist
    mkdir -p "/root/new/frontend/data/$(basename "$filename")"

    # Check if JSON files exist before moving
    if ls "/root/new/root/linux_reports/$(basename "$filename")/"*.json 1> /dev/null 2>&1; then
        mv "/root/new/root/linux_reports/$(basename "$filename")/"*.json "/root/new/frontend/data/$(basename "$filename")"
    else
        echo "Warning: No JSON files found for $filename."
    fi

done

}   

exec_script &
get_file
