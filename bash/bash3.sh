#!/bin/bash
# 
# Name       Date       Description
# -------------------------------------------------------------------
# K. Pejean  22/05/2023   Check if logging is configured
# W. KHLOUF  15/01/2024   Check if logging is configured
# L. ESCOUBOUE 24/03/2025 Check if *.* and *.severity or facility.*

# check-import = stdout

PASSING=true
NON_COMPLIANT_MSG=""
FILES=(/etc/rsyslog.conf /etc/rsyslog.d/*.conf)
STAR_FILE="$(grep -hvE '^#' "${FILES[@]}" 2>/dev/null | grep -E '\*\.\*' | awk '{print $NF}' | sed 's/^-\?//; s/^[[:space:]]*//; s/[[:space:]]*$//')"
REGEX=""
DESCRIPTION=""
ENTRY=""
LOGFILE=""

REGEXS=(
    "\s*\*\.info.*\s+-?/var/log/messages"
    "\s*mail\.none.*\s+-?/var/log/messages"
    "\s*authpriv\.none.*\s+-?/var/log/messages"
    "\s*cron\.none.*\s+-?/var/log/messages"
    "\s*authpriv\.\*.*\s+-?/var/log/secure"
    "\s*mail\.\*.*\s+-?/var/log/maillog"
    "\s*cron\.\*.*\s+-?/var/log/cron"
    "\s*\*\.emerg.*\s-?+:omusrmsg:\*?"
    "\s*uucp\.crit.*\s+-?/var/log/spooler"
    "\s*news\.crit.*\s+-?/var/log/spooler"
    "\s*local7\.\*.*\s+-?/var/log/boot\.log"
)

DESCRIPTIONS=(
    "*.info /var/log/messages"
    "mail.none /var/log/messages"
    "authpriv.none /var/log/messages"
    "cron.none /var/log/messages"
    "authpriv.* /var/log/secure"
    "mail.* /var/log/maillog"
    "cron.* /var/log/cron"
    "*.emerg :omusrmsg:*"
    "uucp.crit /var/log/spooler"
    "news.crit /var/log/spooler"
    "local7.* /var/log/boot.log"
)

 
for i in "${!REGEXS[@]}"; do
        REGEX="${REGEXS[$i]}"
        DESCRIPTION="${DESCRIPTIONS[$i]}"
        ENTRY="$(echo "$DESCRIPTION" | awk '{print $1}' | xargs)"
        LOGFILE="$(echo "$DESCRIPTION" | awk '{print $2}' | xargs)"
        FOUND="false"
        
        # Check if *.* is found on a file and pass the test for all the entry of this file
        if [[ -n "$STAR_FILE" && "$STAR_FILE" == "$LOGFILE" ]]; then
                FOUND="true"
        else
                # Check all the entry
                for file in "${FILES[@]}"; do
                        if [ -f $file ]; then
                                if grep -vE '^#' "$file" | grep -Eq "$REGEX"; then
                                        FOUND="true"
                                fi
                        fi
                done
        fi

        # Check if the entry is found with a star before or after the point.
        if [ "$FOUND" == "false" ]; then
                FACILITY="${ENTRY%%.*}" # Take the first part (for example in "news.crit" it extract "news")
                SEVERITY="${ENTRY##*.}" # Take the last part (for example in "news.crit" it extract "crit")

                for file in "${FILES[@]}"; do
                        if [ -f "$file" ]; then
                                if grep -vE '^#' "$file" | grep -Eq "\s*(.*(${FACILITY}\.\*|\*\.${SEVERITY}).*)\s+-?${LOGFILE}"; then
                                        FOUND="true" 
                                elif grep -vE '^#' "$file" | grep -Eq "^[[:space:]]*([[:alnum:]_]+,)*${FACILITY}(,[[:alnum:]_]+)*\.${SEVERITY}[[:space:]]+-?${LOGFILE}"; then
                                        FOUND="true"
                                else
                                        PASSING="false"
                                fi
                        fi
                done
        fi

        # If the entry is not found, add the description in the non compliant message
        if [ "$FOUND" == "false" ]; then
                NON_COMPLIANT_MSG+="\n$DESCRIPTION"
        fi

done

# Verify if we are compliant
if [ "$PASSING" = "false" ]; then
        echo -e "Check Status Non-Compliant. One or more entry are missing :$NON_COMPLIANT_MSG"
        exit "${XCCDF_RESULT_FAIL:-102}"
else
        echo "Check Status: Compliant."
        exit "${XCCDF_RESULT_PASS:-101}"
fi

