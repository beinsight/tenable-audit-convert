#!/bin/bash
#
# Name          Date         Description
# -------------------------------------------------------------------
# H.GADACHA 21/09/2026 Ensure password reuse is limited

EXPECTED_VALUE=5
FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
PWHISTORY_CONF="/etc/security/pwhistory.conf"
NC_MSG=""
COMPLIANT=true

for FILE in "${FILES[@]}"; do
        if [ ! -f "$FILE" ]; then
                echo "Check Status: Error. The file $FILE does not exist."
                exit "${XCCDF_RESULT_ERROR:-103}"
        fi

        # Fetch target PAM password lines (pam_pwhistory.so and pam_unix.so)
        PAM_LINES=$(grep -P -n '^\h*password\h+.*(pam_pwhistory\.so|pam_unix\.so)' "$FILE")

        if [ -n "$PAM_LINES" ]; then
                while IFS=: read -r LINE CONTENT; do

                        # Check mandatory 'use_authtok' option
                        if [[ ! "$CONTENT" =~ [[:space:]]use_authtok([[:space:]]|$) ]]; then
                                NC_MSG+="\n In $FILE on line $LINE, 'use_authtok' option is missing."
                                COMPLIANT=false
                        fi

                        # Extract control flag
                        if [[ "$CONTENT" =~ ^[[:space:]]*password[[:space:]]+(\[[^\]]+\]|[[:alnum:]_]+) ]]; then
                                FLAG="${BASH_REMATCH[1]}"
                        else
                                FLAG="unknown"
                        fi

                        # Validate control flag (strictly required or requisite, rejecting sufficient due to stack-skipping risk)
                        if [[ "$FLAG" =~ ^\[.*\]$ ]]; then
                                if [[ ! "$FLAG" =~ default=(die|bad) ]]; then
                                        NC_MSG+="\n In $FILE on line $LINE, found flag '$FLAG' expected default=die or default=bad."
                                        COMPLIANT=false
                                fi
                        elif [[ ! "$FLAG" =~ ^(required|requisite)$ ]]; then
                                NC_MSG+="\n In $FILE on line $LINE, found flag '$FLAG' expected required or requisite ('sufficient' is invalid)."
                                COMPLIANT=false
                        fi

                        # Check 'remember' value for pam_pwhistory.so (line override or pwhistory.conf inheritance)
                        if [[ "$CONTENT" =~ "pam_pwhistory.so" ]]; then
                                if [[ "$CONTENT" =~ remember=([0-9]+) ]]; then
                                        VALUE="${BASH_REMATCH[1]}"
                                        if [ "$VALUE" -lt "$EXPECTED_VALUE" ]; then
                                                NC_MSG+="\n In $FILE on line $LINE, the value 'remember=$VALUE' must be greater than or equal to $EXPECTED_VALUE."
                                                COMPLIANT=false
                                        fi
                                else
                                        if [ -f "$PWHISTORY_CONF" ]; then
                                                CONF_REMEMBER=$(grep -P '^\h*remember\h*=\h*([0-9]+)' "$PWHISTORY_CONF" | awk -F= '{print $2}' | tr -d '[:space:]')
                                                
                                                if [ -n "$CONF_REMEMBER" ]; then
                                                        if [ "$CONF_REMEMBER" -lt "$EXPECTED_VALUE" ]; then
                                                                NC_MSG+="\n In $FILE on line $LINE, 'remember' is inherited from $PWHISTORY_CONF but its value '$CONF_REMEMBER' is less than $EXPECTED_VALUE."
                                                                COMPLIANT=false
                                                        fi
                                                else
                                                        NC_MSG+="\n In $FILE on line $LINE, 'remember' parameter is not set in $PWHISTORY_CONF."
                                                        COMPLIANT=false
                                                fi
                                        else
                                                NC_MSG+="\n In $FILE on line $LINE, 'remember' is not set and configuration file $PWHISTORY_CONF is missing."
                                                COMPLIANT=false
                                        fi
                                fi
                        fi

                done <<< "$PAM_LINES"
        else
                NC_MSG+="\n The password module (pam_pwhistory.so or pam_unix.so) is missing in the file $FILE"
                COMPLIANT=false
        fi
done

if [ "$COMPLIANT" = false ]; then
        echo -e "Check Status : Non-Compliant. $NC_MSG"
        exit "${XCCDF_RESULT_FAIL:-102}"
else
        echo "Check Status : Compliant."
        exit "${XCCDF_RESULT_PASS:-101}"
fi

