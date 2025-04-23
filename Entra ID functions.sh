#!/bin/zsh

#################################################
# The Entra ID token examples here are all using
# Application permissions. If you are getting a
# token as a user, then the Delegated permissions
# that are noted would instead apply.
#################################################

#################################################
# Entra ID Authentication
#################################################
# Fake values - Replace with your own:
entraTenant="42B8127A-805D-44C9-A189-8041E63E44F7"
entraAppId="8C2CF26A-6464-4641-9802-58DF78FE5F20"
entraSecret="F37CE~BQxFKiA8BWE21x99gP8lDlFhfwj2hZEbnz"

#################################################
# https://jqlang.github.io/jq/
#################################################
# jq is included with macOS Sequoia (15) and later
#
# If you are using a macOS prior to that, you need
#    to provide the binary and update the path here:
#################################################
# Check if jq is available and set the jqCmd variable accordingly
if [[ -x "/usr/bin/jq" ]]; then
    jqCmd="/usr/bin/jq"
elif [[ -x "/usr/local/bin/jq" ]]; then
    jqCmd="/usr/local/bin/jq"
else
    echo "jq not found. Please install jq." 
    echo "Make sure it is in either /usr/bin/jq or /usr/local/bin/jq."
    exit 1
fi

#################################################
# Logging Function
#################################################
# Log location can be overridden with an environment variable
log_location="${LOG_LOCATION:-~/Library/Logs/entra-group.log}"

if [ ! -d "$(dirname "$log_location")" ]; then
    mkdir -p "$(dirname "$log_location")"
fi

function printlog() {
    message="${1}"
    timestamp=$(/bin/date "+%F %T")
    
    if [[ "$(/usr/bin/whoami)" == "root" ]]; then
       echo "${timestamp} :: ${message}" | /usr/bin/tee -a "${log_location}"
    else
       echo "${timestamp} :: ${message}"
    fi
}

#################################################
#  ----    ----    JWT Decoder    ----    ----
#################################################
# Usage:
#  jwtDecode "$accessToken"
#
function jwtDecode() {
  "${jqCmd}" -R 'split(".") |.[0:2] | map(gsub("-"; "+") | gsub("_"; "/") | gsub("%3D"; "=") | @base64d) | map(fromjson)' <<< $1
}

#################################################
# ----   ----   Entra ID Functions   ----   ----
#################################################

#################################################
# Get an Entra ID token using Client Secret.
#################################################
function getEntraAuthTokenUsingSecret() {
    ####################################
    # https://learn.microsoft.com/en-us/graph/auth-v2-service?tabs=curl
    ####################################

    ####################################
    # Clear any previous token
    ####################################
    tokenResult=""
    accessToken=""
    ####################################
    # Request an access token
    ####################################
    tokenResult=$(/usr/bin/curl --silent --fail --location \
    --request "POST" "https://login.microsoftonline.com/${entraTenant}/oauth2/token" \
    --header 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
    --data-urlencode "client_id=${entraAppId}" \
    --data-urlencode "scope=https://graph.microsoft.com/.default" \
    --data-urlencode "Resource=https://graph.microsoft.com/" \
    --data-urlencode "client_secret=${entraSecret}" \
    --data-urlencode "grant_type=client_credentials")
    
    tokenResultExit=$?

    accessToken=$(echo "${tokenResult}" | "${jqCmd}" -r '.access_token')
}

#################################################
# Lookup Intune record matching the computer serial number.
#################################################
function lookupIntuneDeviceRecordFromSerial() {
    ####################################
    # https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0
    ####################################
    # Delegated
    #    DeviceManagementManagedDevices.Read.All
    #
    # Application
    #    DeviceManagementManagedDevices.Read.All
    ####################################

    ####################################
    # Get the  serial number to find the managed device
    ####################################
    serialNumber=$(/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/awk '/Serial/ {print $4}')

    ####################################
    ## Get a managedDevice, from a serial number (".value[0] .id") 
    ####################################
    managedDeviceResult=$(/usr/bin/curl --silent --fail \
    "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?\$filter=serialNumber%20eq%20%27${serialNumber}%27" \
    --header "Authorization: Bearer ${accessToken}" \
    --header 'Content-Type: application/x-www-form-urlencoded; charset=utf-8')

    managedDeviceResultExit=$?

    # Save the results to a json file
    echo "managedDeviceResult:"
    echo "${managedDeviceResult}" | "${jqCmd}"
    echo ""
}

function lookupEntraDeviceRecordFromAadDeviceID() {
    ####################################
    # https://learn.microsoft.com/en-us/graph/api/device-list?view=graph-rest-1.0&tabs=http
    ####################################
    # Delegated
    #    Device.Read.All
    #    (In delegated scenarios, the signed-in user must also
    #        be assigned a supported Microsoft Entra role or a
    #        custom role with the role permission)
    #
    # Application
    #    Device.Read.All
    ####################################
    
    ####################################
    # Get a Device, from aadDeviceID
    ####################################
    entraDeviceResult=$(/usr/bin/curl --silent --fail \
    "https://graph.microsoft.com/v1.0/devices?\$filter=deviceID%20eq%20%27${azureADDeviceId}%27" \
    --header "Authorization: Bearer ${accessToken}" \
    --header 'Content-Type: application/x-www-form-urlencoded; charset=utf-8')

    entraDeviceResultExit=$?
    
    echo "entraDeviceResult:"
    echo "${entraDeviceResult}" | "${jqCmd}"
    echo ""
}

function addDeviceToEntraSecurityGroup() {
    ####################################
    # (You need the GUID ID of the group)
    ####################################    
    entraGroup="450AE7CB-1AC9-4B47-844D-CEDFF44AE44E"

    ####################################
    # https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http
    ####################################
    # Delegated
    #    GroupMember.ReadWrite.All
    #    Device.ReadWrite.All
    #    (In delegated scenarios, the signed-in user must also be assigned
    #        a supported Microsoft Entra role or a custom role with the
    #        microsoft.directory/groups/members/update role permission)
    #
    # Application
    #    GroupMember.ReadWrite.All
    #    Device.ReadWrite.All
    ####################################
    
    ####################################
    # Add computer to group
    ####################################
    groupAddResult=$(/usr/bin/curl --silent --fail --location \
    --request "POST" "https://graph.microsoft.com/v1.0/groups/${entraGroup}/members/\$ref" \
    --header "Authorization: Bearer ${accessToken}" \
    --header 'Content-Type: application/json' \
    --data "{\"@odata.id\": \"https://graph.microsoft.com/v1.0/devices/${aadDeviceID}\"}")

    groupAddResultExitCode=$?
    
#     echo "groupAddResult = ${groupAddResult}"
#     echo "groupAddResultExitCode = ${groupAddResultExitCode}"
}

function setIntuneDeviceCategory() {
    ####################################
    # (You need the GUID ID of the Category)
    ####################################    
    deviceCategory="450AE7CB-1AC9-4B47-844D-CEDFF44AE44E"
    
    ####################################
    # Set device category to "Company Owned"
    ####################################
    if [[ ! -z "${deviceID}"  ]];  then
        setCategoryResult=$(/usr/bin/curl --silent --fail --location \
        --request PUT "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${deviceID}/deviceCategory/\$ref" \
        --header "Authorization: Bearer ${accessToken}" \
        --header 'Content-Type: application/json' \
        --data "{\"@odata.id\": \"https://graph.microsoft.com/v1.0/deviceManagement/deviceCategories/${deviceCategory}\"}")
    fi
    
    setCategoryResultExit=$?
    
    printlog "setCategoryResult = ${setCategoryResult}"
    printlog "setCategoryResultExit = ${setCategoryResultExit}"
    printlog ""
}

function syncDeviceWithIntune() {
    ####################################
    # https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-syncdevice?view=graph-rest-1.0&tabs=http
    ####################################
    # Delegated
    #    DeviceManagementManagedDevices.PrivilegedOperations.All
    #
    # Application
    #    DeviceManagementManagedDevices.PrivilegedOperations.All
    ####################################

    ####################################
    # Sync device with Intune
    ####################################
    ## send the syncDevice command
    syncDeviceResult=$(/usr/bin/curl --silent --fail --location \
    --request "POST" "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${deviceID}/syncDevice" \
    --header "Authorization: Bearer ${accessToken}" \
    --header 'Content-Type: application/json')

    syncDeviceResultExit=$?

#     echo "syncDeviceResult = ${syncDeviceResult}"
#     echo "syncDeviceResultExit = ${syncDeviceResultExit}"


    if [[ -z "${syncDeviceResult}" ]];  then
        printlog "syncDevice sent to ${serialNumber}"
    fi

}

#################################################
# ---   ---   Data Handling Functions   ---   ---
#################################################

function assignManagedDeviceAttributeValues() {
    ####################################
    # (Call the lookupIntuneDeviceRecord function before this)
    ####################################
    
    ####################################
    # Get attributes from the json results
    ####################################
    azureADDeviceId=$(echo "${managedDeviceResult}" | "${jqCmd}" -r '.value[0] .azureADDeviceId // "Unknown"')
    deviceID=$(echo "${managedDeviceResult}" | "${jqCmd}" -r '.value[0] .id // "Unknown"')
    deviceName=$(echo "${managedDeviceResult}" | "${jqCmd}" -r '.value[0] .deviceName // "Unknown"')
    emailAddress=$(echo "${managedDeviceResult}" | "${jqCmd}" -r '.value[0] .emailAddress // "Unknown"')
    enrolledDateTime=$(echo "${managedDeviceResult}" | "${jqCmd}" -r '.value[0] .enrolledDateTime // "Unknown"')
    userID=$(echo "${managedDeviceResult}" | "${jqCmd}" -r '.value[0] .userId // "Unknown"')
    userDisplayName=$(echo "${managedDeviceResult}" | "${jqCmd}" -r '.value[0] .userDisplayName // "Unknown"')    
    userPrincipalName=$(echo "${managedDeviceResult}" | "${jqCmd}" -r '.value[0] .userPrincipalName // "Unknown"')    
}

function echoManagedDeviceAttributeValues() {
    ####################################
    # (Call the getManagedDeviceAttributeValues function before this)
    ####################################
    
    ####################################
    # Get attributes from the json results
    ####################################
    echo "Intune Attributes"
    echo "---------------------------------------------"
    echo "azureADDeviceId: $azureADDeviceId"
    echo "deviceID: $deviceID"
    echo "deviceName: $deviceName"
    echo "emailAddress: $emailAddress"
    echo "enrolledDateTime: $enrolledDateTime"
    echo "userID: $userID"
    echo "userDisplayName: $userDisplayName"
    echo "userPrincipalName: $userPrincipalName"
    echo ""
}

function writeManagedDeviceAttributeValuesToPlist() {
    ####################################
    # (Call the getManagedDeviceAttributes function before this)
    ####################################
    
    ####################################
    # Save attributes locally for possible use later
    ####################################
    managedDevicePlist="/tmp/managedDeviceResult.plist"

    /usr/bin/defaults write "${managedDevicePlist}" azureADDeviceId "${azureADDeviceId}"
    /usr/bin/defaults write "${managedDevicePlist}" deviceID "${deviceID}"
    /usr/bin/defaults write "${managedDevicePlist}" deviceName "${deviceName}"
    /usr/bin/defaults write "${managedDevicePlist}" emailAddress "${emailAddress}"
    /usr/bin/defaults write "${managedDevicePlist}" enrolledDateTime "${enrolledDateTime}"
    /usr/bin/defaults write "${managedDevicePlist}" userDisplayName "${userDisplayName}"
    /usr/bin/defaults write "${managedDevicePlist}" userID "${userID}"
    /usr/bin/defaults write "${managedDevicePlist}" userPrincipalName "${userPrincipalName}"

    /bin/chmod +r "${managedDevicePlist}"

}


function assignEntraDeviceAttributeValues() {
    ####################################
    # (Call the lookupEntraDeviceRecordFromAadDeviceID function before this)
    ####################################
    
    ####################################
    # Get attributes from the json results
    ####################################
    deviceCategory=$(echo "${entraDeviceResult}" | "${jqCmd}" -r '.value[0] .deviceCategory // "Unknown"')
    deviceOwnership=$(echo "${entraDeviceResult}" | "${jqCmd}" -r '.value[0] .deviceOwnership // "Unknown"')
    displayName=$(echo "${entraDeviceResult}" | "${jqCmd}" -r '.value[0] .displayName // "Unknown"')
    enrollmentProfileName=$(echo "${entraDeviceResult}" | "${jqCmd}" -r '.value[0] .enrollmentProfileName // "Unknown"')
    enrollmentType=$(echo "${entraDeviceResult}" | "${jqCmd}" -r '.value[0] .enrollmentType // "Unknown"')
    isCompliant=$(echo "${entraDeviceResult}" | "${jqCmd}" -r '.value[0] .isCompliant // "Unknown"')    
    isManaged=$(echo "${entraDeviceResult}" | "${jqCmd}" -r '.value[0] .isManaged // "Unknown"')    
}

function echoEntraDeviceAttributeValues() {
    ####################################
    # (Call the getEntraDeviceAttributeValues function before this)
    ####################################
    
    ####################################
    # Get attributes from the json results
    ####################################
    echo "Entra ID Attributes"
    echo "---------------------------------------------"
    echo "deviceCategory: $deviceCategory"
    echo "deviceOwnership: $deviceOwnership"
    echo "displayName: $displayName"
    echo "enrollmentProfileName: $enrollmentProfileName"
    echo "enrolledDateTime: $enrolledDateTime"
    echo "enrollmentType: $enrollmentType"
    echo "isCompliant: $isCompliant"
    echo "isManaged: $isManaged"
    echo ""
}

#################################################
# Do the stuff
#################################################
# Get a token
getEntraAuthTokenUsingSecret

# Lookup Intune Device Info
lookupIntuneDeviceRecordFromSerial
assignManagedDeviceAttributeValues
echoManagedDeviceAttributeValues

# Lookup Entra Device Info
lookupEntraDeviceRecordFromAadDeviceID
assignEntraDeviceAttributeValues
echoEntraDeviceAttributeValues

#################################################
# Optional function examples not called
#################################################
# addDeviceToEntraSecurityGroup
# setIntuneDeviceCategory
# syncDeviceWithIntune
# writeManagedDeviceAttributeValuesToPlist
# jwtDecode "$accessToken"

exit 0