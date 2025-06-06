
#region Module Variables
$global:PgSqlConfig = $null
$global:sqlkeywords = @(
    'ALL', 'ANALYSE', 'ANALYZE', 'AND', 'ANY', 'ARRAY', 'AS', 'ASC', 'ASYMMETRIC', 'BOTH', 'CASE', 'CAST', 'CHECK', 'COLLATE', 'COLUMN', 'CONSTRAINT', 'CREATE', 'CURRENT_DATE', 'CURRENT_ROLE', 'CURRENT_TIME', 'CURRENT_TIMESTAMP', 'CURRENT_USER', 'DEFAULT', 'DEFERRABLE', 'DESC', 'DISTINCT', 'DO', 'ELSE', 'END', 'EXCEPT', 'FALSE', 'FOR', 'FOREIGN', 'FROM', 'GRANT', 'GROUP', 'HAVING', 'IN', 'INITIALLY', 'INTERSECT', 'INTO', 'LEADING', 'LIMIT', 'LOCALTIME', 'LOCALTIMESTAMP', 'NEW', 'NOT', 'NULL', 'OFF', 'OFFSET', 'OLD', 'ON', 'ONLY', 'OR', 'ORDER', 'PLACING', 'PRIMARY', 'REFERENCES', 'SELECT', 'SESSION_USER', 'SOME', 'SYMMETRIC', 'TABLE', 'THEN', 'TO', 'TRAILING', 'TRUE', 'UNION', 'UNIQUE', 'USER', 'USING', 'WHEN', 'WHERE'
)
#endregion




Function Get-PgSqlModulePath {
    <#
    .SYNOPSIS
        Returns the module base path.
    .DESCRIPTION
        Returns the base directory of the current module.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()
    return $MyInvocation.MyCommand.Module.ModuleBase
}


Function Test-PgSqlConfig {
    <#
    .SYNOPSIS
        Ensures the PostgreSQL config file exists and is valid.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )
    $ModulePath = Get-PgSqlModulePath
    $ConfigPath = Join-Path $ModulePath 'config.json'

    if ($null -eq $global:PgSqlConfig -or $Force) {

        if (!(Test-Path $ConfigPath)) {
            Write-Warning "PostgreSQL config file not found at $ConfigPath"
            Set-PgSqlConfig
        }
        else {
            try {
                $global:PgSqlConfig = Get-Content $ConfigPath | ConvertFrom-Json
            }
            catch {
                Write-Error "PostgreSQL config file is invalid at $ConfigPath"
                Set-PgSqlConfig
            }
            if ($null -eq $global:PgSqlConfig) {
                Write-Error "PostgreSQL config file is empty or invalid at $ConfigPath"
                Set-PgSqlConfig
            }
        }
    }
}



Function Set-PgSqlConfig {
    <#
    .SYNOPSIS
        Prompts for and sets the PostgreSQL configuration.
    #>
    [CmdletBinding()]
    param ()
    $ModulePath = Get-PgSqlModulePath
    $ConfigPath = Join-Path $ModulePath 'config.json'

    $Server = Read-Host -Prompt 'Enter PostgreSQL Server'
    $Database = Read-Host -Prompt 'Enter PostgreSQL Database'
    $User = Read-Host -Prompt 'Enter PostgreSQL User'
    $Password = Read-Host -Prompt 'Enter PostgreSQL Password' -AsSecureString
    $PasswordString = $Password | ConvertFrom-SecureString
    $EnableCachedTableDefinitions = Read-Host -Prompt 'Enable Cached Table Definitions? (Y/N) (Increases performance by caching table definitions in memory)'
    $global:PgSqlConfig = @{
        Server                       = $Server
        Database                     = $Database
        User                         = $User
        Password                     = $PasswordString
        EnableCachedTableDefinitions = if ($EnableCachedTableDefinitions -eq 'Y') { $true } else { $false }
    }
    if ($null -ne $global:PgSqlConfig) {
        $global:PgSqlConfig | ConvertTo-Json | Out-File -FilePath $ConfigPath
        Write-Host -ForegroundColor Green 'Config file created successfully'
    }
}


Function Get-PgSqlConfig {
    <#
    .SYNOPSIS
        Retrieves the current PostgreSQL configuration
    .DESCRIPTION
        Retrieves the current PostgreSQL configuration from the config.json file in the module directory.
    .EXAMPLE
        Get-PgSqlConfig
    #>
    [CmdletBinding()]
    param ()
    if ($null -eq $global:PgSqlConfig) {
        Set-PgSqlConfig
    }
    return $global:PgSqlConfig
}



Function Test-PGODBCDriver {
    <#
    .SYNOPSIS
        Checks to see if the PostgreSQL ODBC Driver is installed
    .DESCRIPTION
        Generates a terminating error if the PostgreSQL ODBC Driver can not be found. Only has to run this check once per session.
    #>
    
    if ($PostgreSQLODBCDriverPresent -ne $true) {

        if ($null -eq (Get-OdbcDriver -Name *PostgreSQL*)) {
            Get-LatestPGODBCDriver
        }
        else {
            $global:PostgreSQLODBCDriverPresent = $true
        }
    }
}

Function Get-LatestPGODBCDriver {
    $ModulePath = Get-PgSqlModulePath

    $uri = "https://api.github.com/repos/postgresql-interfaces/psqlodbc/releases/latest"

    $headers = @{
        'User-Agent' = 'PowerShell'
    }

    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    $latestmsi = $response.assets | Where-Object { $_.name -eq "psqlodbc_x64.msi" } 

    $assetUri = $latestmsi.browser_download_url
    $assetName = $latestmsi.name
    Write-Host "Downloading $assetName from $assetUri"
    
    Start-BitsTransfer -Source $assetUri -Destination $ModulePath
    Write-Host "Downloaded $assetName"

    write-host "installed $assetname from $modulepath"
    Start-Process msiexec -ArgumentList "/i `"$ModulePath\$assetName`" /qn /norestart" -Wait -NoNewWindow
    write-host "Installed $assetName"

}

Function Get-PGSQLTableDefinitions {
    param(
        [switch]
        $Force
    )
    <#
    .SYNOPSIS
        Retrieves all column information from DB
    .DESCRIPTION
        Stores all table schemas, table names, column names, and column data types for quick retrieval. Module must be forcibly imported to update the table definitions variable.
    .NOTES
        This function exists to reduce the amount of queries done against the DB. By storing the table definitions in a variable, we can reference this in memory instead of querying the DB before each insert.
    #>
    if ('' -eq [string]$tabledefinitions -or $Force) {
        try {

            $query = @'
    SELECT table_schema,table_name,column_name,data_type,is_nullable
    FROM information_schema.columns
    where table_schema not like '%timescaledb_%'
    and table_schema not in ('information_schema','pg_catalog')
'@
            [System.Data.Odbc.OdbcCommand]$pgsqlcmd = New-Object System.Data.Odbc.OdbcCommand($query, $PgSqlConnection)
            [System.Data.Odbc.odbcDataAdapter]$pgsqlda = New-Object system.Data.odbc.odbcDataAdapter($pgsqlcmd)    
            $pgsqlds = [System.Data.DataSet]::new()
            [void]$pgsqlda.Fill($pgsqlds)

            $global:tabledefinitions = $pgsqlds.Tables.Rows

        }
        catch {
            Write-Error "Failed to retrieve table definitions: $($_.Exception.Message)"
            return
        }
        finally {
            if ($null -ne $pgsqlcmd) { $pgsqlcmd.Dispose() }
            if ($null -ne $pgsqlda) { $pgsqlda.Dispose() }
            if ($null -ne $pgsqlds) { $pgsqlds.Dispose() }
            $PgSqlConnection.Close()
        }
    }
}


Function Connect-PgSqlServer {
    <#
    .SYNOPSIS
        Connects to the PostgreSQL server using the configuration.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $User,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Password,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Database,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Server,
        [Parameter()]
        [int]
        $Port = 5432,
        [Parameter()]
        [switch]
        $Force
    )

    Test-PgSqlConfig
    Test-PGODBCDriver


    if ($Null -eq $PSBoundParameters['User'] ) {
        $PSBoundParameters['User'] = $global:PgSqlConfig.User
    }
    if ($Null -eq $PSBoundParameters['Password'] ) {
        $PSBoundParameters['Password'] = $global:PgSqlConfig.Password
    }
    if ($Null -eq $PSBoundParameters['Database'] ) {
        $PSBoundParameters['Database'] = $global:PgSqlConfig.Database
    }
    if ($Null -eq $PSBoundParameters['Server'] ) {
        $PSBoundParameters['Server'] = $global:PgSqlConfig.Server
    }
    

    
  
    try {
        if ($null -eq $global:PgSqlConnection -or $Force -or $PgSqlConnection.ConnectionString -ne "Driver={PostgreSQL Unicode(x64)};Server=$($PSBoundParameters['Server']);Port=$Port;Database=$($PSBoundParameters['Database']);Uid=$($PSBoundParameters['User'] );Pwd=$($PSBoundParameters['Password']);Pooling=true;") {
            $PgSqlConnection = New-Object System.Data.Odbc.OdbcConnection
            $PgSqlConnection.ConnectionString = "Driver={PostgreSQL Unicode(x64)};Server=$($PSBoundParameters['Server']);Port=$Port;Database=$($PSBoundParameters['Database']);Uid=$($PSBoundParameters['User'] );Pwd=$($PSBoundParameters['Password']);Pooling=true;"
            $PgSqlConnection.ConnectionTimeout = 60
            $PgSqlConnection.Open()
            $global:PgSqlConnection = $PgSqlConnection
        }
        elseif ($PgSqlConnection.State -eq 'Closed') {
            $PgSqlConnection.Open()
        }
        Get-PGSQLTableDefinitions
    }
    catch {
        $ip = (Get-NetIPAddress | Where-Object { $_.InterfaceIndex -in ((Get-NetAdapter | Where-Object { $_.status -eq 'Up' }).ifindex) -and $_.AddressFamily -eq 'IPv4' }).IPAddress
        Write-Error "Postgresql Connection Failed. If necessary, make sure your Postgresql server is listening on non-local ports and your pg_hba.conf has been modified accordingly. You may need an entry such as 'host all all $ip/32 trust'"
        throw $_.Exception
    }
    
}

Function Disconnect-PGSQLServer {
    <#
.SYNOPSIS
Disconnect from current $PgSqlConnection
#>
    try {
        if ($PgSqlConnection.State -eq 'Open') {
            $PgSqlConnection.Close()
        }
    }
    catch {
        $_.exception.message
    }

}

Function Invoke-PGSQLSelect {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Query
    )

    Connect-PGSQLServer
    try {
        [System.Data.Odbc.OdbcCommand]$pgsqlcmd = New-Object System.Data.Odbc.OdbcCommand($query, $PgSqlConnection)
        [System.Data.Odbc.odbcDataAdapter]$pgsqlda = New-Object system.Data.odbc.odbcDataAdapter($pgsqlcmd)    
        $pgsqlds = [System.Data.DataSet]::new()
        [void]$pgsqlda.Fill($pgsqlds)
        return $pgsqlds.Tables.Rows
    }
    catch {
        throw $_.exception
    }
    finally {
        $pgsqlcmd.Dispose()
        $pgsqlda.Dispose()
        $pgsqlds.Dispose()
    }
   
}

Function Set-PGSQLInsert {
    <#
    .SYNOPSIS
        Builds a Postgresql insert query statement
    .DESCRIPTION
        Used by the "Invoke-PGSQLInsert" function, this function builds the entire insert query statement and creates a single large insert statement instead of multiple single inserts.
    .NOTES
        This function has multiple functionalities:
            - Queries the DB to try and best-match the columns in your $InputObject variable. This allows you to not specify object properties while only inserting properties(columns) that already exist in the table.
            - Normalizes property names (removes certain special characters and changes the case to lower)
            - Identifies primary keys for use with "ON CONFLICT" and "DO UPDATE SET" (for updating data without truncating the table)
            - Automatically replaces single quotes with double single quotes
            - Handles null values (and weird stuff like [dbnull]) by always converting all values to a string with [string]$member.value 
            - Automatically wraps Postgresql key words with double quotes
            - Automatically wraps schema names with double quotes in case of upper case characters
    .EXAMPLE
        Set-PGSQLInsert -InputObject $InputObject -OnConflict 'Set Excluded' -Schema activedirectory -Table computers
    #>
    
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $InputObject,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Do Nothing', 'Set Excluded', 'null')]
        [string]
        $OnConflict,
        [Parameter(Mandatory = $true)]
        [string]
        $Schema,
        [Parameter(Mandatory = $true)]
        [string]
        $Table
    )
    try {
        $schema = $Schema
        $table = $table
        $columns = @()
        $values = $null
        $definitions = @()
        $pgColumns = @()
        $insertstatement = $null
        $Columns = ($InputObject | Get-Member).Where({ $_.membertype -in ('Property', 'NoteProperty') }) | Select-Object name,
        @{name = 'Property'; expression = { $_.name.trim().tolower() -replace '(\(|\)|\%)', '' -replace '( |/|-)', '_' } }, 
        @{name = 'DataType'; expression = { $_.definition.split(' ')[0] } } -Unique | Sort-Object -Property name

        if ($PgSqlConfig.EnableCachedTableDefinitions -eq $true) {
            $definitions = $tabledefinitions | Where-Object { $_.table_schema -ceq $schema -and $_.table_name -ceq $table } | Select-Object column_name, data_type, is_nullable
        }
        else {
            $definitions = Invoke-PGSQLSelect -Query "SELECT column_name,data_type,is_nullable FROM information_schema.columns WHERE table_schema = '$schema' and table_name = '$table'"
        }
        if (!$definitions) {
            Write-Error "$schema.$table - Does not exist"
            return
        }

        $pgColumns = $columns.Where({ $_.property -in $definitions.column_name })
        $comparecolumns = ($inputobject[0].psobject.properties).name.trim().tolower() -replace '(\(|\)|\%)', '' -replace '( |/|-)', '_'
        $insertcolumns = @()
        $selcolumns = @()
        foreach ($column in $comparecolumns) {
            if ($column -in $pgColumns.property) {
                $column = $pgColumns.where({ $_.Property -eq $column })
                if ($column.Property -in $sqlkeywords) { $insertcolumns += '"' + "$($column.Property)" + '"' }else { $insertcolumns += $column.Property }
                $selcolumns += $column.name
            }
        }

        if (-not (Compare-Object @($comparecolumns) @($pgcolumns.name)) ) {
        }
        else {
            $InputObject = $InputObject | Select-Object -Property $selcolumns
        }

        $pgcolumns_string = [System.String]::Join(', ', $insertcolumns)
        $pkeys = ($definitions.Where({ [string]$_.is_nullable -eq 'NO' })).column_name
        if ($null -eq $pkeys) {
            Write-Error 'Primary Keys have not been defined'
            break
        }
        $pkeys_string = [System.String]::Join(',', $pkeys)
        $excluded = ($definitions.Where({ [string]$_.is_nullable -eq 'YES' })).column_name
            
        $values = [System.String]::Join(',', (& { foreach ($property in $InputObject) {
                        $membervalues = foreach ($member in $($property.psobject.properties)) {
                            $membervalue = [string]$member.value
                            if ($membervalue) { "'" + $membervalue.Replace("'", "''") + "'" }else { 'Null' }
                        } 
                        '(' + [System.String]::Join(',', $membervalues) + ')'
                    } }))


        switch ($onconflict) {
            'Set Excluded' { 
                if ($excluded) {
                    $excludedcolumns = foreach ($exc in $excluded) {
                        if ($exc -in $sqlkeywords) { $exc = "`"$exc`"" }
                        "$exc=EXCLUDED.$exc"
                    }
                    $excludedcolumns = [System.String]::Join(',', $excludedcolumns)
                    $conflictstatement = "ON CONFLICT ($pkeys_string) DO UPDATE SET $excludedcolumns"
                }
                else {
                    $conflictstatement = 'ON CONFLICT DO NOTHING'
                }
                break
            }
            'Do Nothing' {
                $conflictstatement = 'ON CONFLICT DO NOTHING'
                break
            }
            'null' {
                $conflictstatement = $null 
                break
            }
            Default { $conflictstatement = $null }
        }

        if ($schema -cmatch '[A-Z]') { $insertinto = "`"$($schema)`".$table ($pgcolumns_string)" } else { $insertinto = "$($schema).$table ($pgcolumns_string)" }

        $insertstatement = @"
    INSERT INTO $insertinto
    VALUES $values
    $conflictstatement;
"@
    
        return $insertstatement
    }
    catch {
        $_.Exception
    }
    finally {
        $values = $null
        $insertstatement = $null
    }
}
Function Invoke-PGSQLTruncate {
    <#
    .SYNOPSIS
        Truncates a Postgresql table
    .DESCRIPTION
        Executes a truncate table query on the specified table
    .EXAMPLE
        Invoke-PGSQLTruncate -Schema 'activedirectory' -Table 'computers'
    #>
    
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Schema,
        [Parameter(Mandatory = $true)]
        [string]
        $Table
    )
 
    $truncatestatement = Set-PGSQLTruncate -Schema $Schema -Table $Table
    try {
        [System.Data.Odbc.OdbcCommand]$truncatecmd = New-Object System.Data.Odbc.OdbcCommand($truncatestatement, $PgSqlConnection)
        [void]$truncatecmd.ExecuteNonQuery()
    }
    catch {
        Write-Error $_.Exception
    }
    finally {
        $truncatecmd.Dispose()
    }

    
}

Function Set-PGSQLTruncate {
    <#
    .SYNOPSIS
        Builds a Postgresql truncate query statement
    .DESCRIPTION
        Builds a Postgresql truncate query statement using the specified schema and table
    .EXAMPLE
        Set-PGSQLTruncate -Schema 'activedirectory' -Table 'computers'
    #>
    
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Schema,
        [Parameter(Mandatory = $true)]
        [string]
        $Table
    )
 
    if ($schema -cmatch '[A-Z]') { $truncatestatement = "truncate table `"$($schema)`".$table;" }
    else { $truncatestatement = "truncate table $($schema).$table;" }
    
    return $truncatestatement
    
}
Function Invoke-PGSQLInsert {
    <#
    .SYNOPSIS
        A short one-line action-based description, e.g. 'Tests if a function is valid'
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        Specify a URI to a help page, this will show when Get-Help -Online is used.
    .EXAMPLE
        # Complete Copy: You want to store an up-to-date copy of your Active Directory computers and want a clean/fresh set of data, truncate the existing table

        Invoke-PGSQLInsert -InputObject $InputObject -OnConflict 'Do Nothing' -Schema 'activedirectory' -Table 'computers' -Truncate $true
    .EXAMPLE
        # Time Series Data:  You want to track metrics over time and don't want to truncate the table. By setting -OnConflict to 'Set Excluded', we can update the data in the 'Value' column (assuming the Date and Metric columns are set as primary keys)
        $InputObject = [PSCustomObject]@{
                        Date = (Get-date).tostring('yyyy-MM-dd')
                        'Metric' = 'Total Machines'
                        'Value' = 12345
                        }

        Invoke-PGSQLInsert -InputObject $InputObject -OnConflict 'Set Excluded' -Schema 'activedirectory' -Table 'total_machines_history' -Truncate $false
    #>
    
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $InputObject,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Do Nothing', 'Set Excluded', 'null')]
        [string]
        $OnConflict,
        [Parameter(Mandatory = $true)]
        [string]
        $Schema,
        [Parameter(Mandatory = $true)]
        [string]
        $Table,
        [Parameter(Mandatory = $true)]
        [ValidateSet($true, $false)]
        [bool]
        $Truncate
    )

    $PgInsertQuery = $null
    if ($truncate -eq $true) {
        $PgInsertQuery = Set-PGSQLTruncate -Schema $Schema -Table $Table
    }

    $PgInsertQuery += Set-PGSQLInsert -InputObject $InputObject -OnConflict $OnConflict -Schema $Schema -Table $Table


    try {
        [System.Data.Odbc.odbcDataAdapter]$da = New-Object system.Data.odbc.odbcDataAdapter
        $da.InsertCommand = New-Object System.Data.Odbc.OdbcCommand($PgInsertQuery, $PgSqlConnection)
        $da.InsertCommand.Prepare()
        [void]$da.InsertCommand.ExecuteNonQuery()

    }
    catch {
        Write-Error $_
    }
    finally {
        $da.Dispose()
    }
    
}

Function Add-PGSQLTable {

    <#
    .SYNOPSIS
        Creates a Postgresql table using a powershell object
    .DESCRIPTION
        This function will create a postgresql table based on the input object. A GUI will be displayed where you can choose schema name, table name, primary keys, and columns/data types
    .NOTES
        This function replaces certain special characters in property names with "-replace '(\(|\)|\%)', '' -replace '( |/|-)', '_'" and also converts all column names to lower case

        This function assumes you have a group called "readonly" that you use to give select permissions

    CREATE ROLE readonly WITH
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    INHERIT
    NOREPLICATION
    NOBYPASSRLS
    CONNECTION LIMIT -1;

    .EXAMPLE
        Add-PGSQLTable -InputObject $inputobject
    .EXAMPLE
        Add-PGSQLTable -InputObject $inputobject -GrantReadOnly -ReadOnlyGroup 'read_only_users'
    .EXAMPLE
        Add-PGSQLTable -InputObject $inputobject -Table 'Computers' -Schema 'ActiveDirectory' -PrimaryKeys @('ObjectGUID')
    #>
    
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [psobject]
        $InputObject,
        # Shows PowerShell object in Out-Gridview.
        [Parameter(HelpMessage = 'Shows PowerShell object in Out-Gridview.')]
        [switch]
        $GridView,
        # Grant permission to specified ReadOnly group.
        [Parameter(
            Position = 1,
            ParameterSetName = 'ReadOnly',
            Mandatory = $false,
            HelpMessage = 'Grant permission to specified ReadOnly group.')]
        [switch]
        $GrantReadOnly,
        # ReadOnly group to grant permissions to.
        [Parameter(
            Position = 2,
            ParameterSetName = 'ReadOnly',
            Mandatory = $false,
            HelpMessage = 'ReadOnly group to grant permissions to.')
        ]
        [string]
        $ReadOnlyGroup,
        [string]
        $Table,
        [string]
        $Schema,
        [array]
        $PrimaryKeys
    )
    
    begin {
        Connect-PGSQLServer
        if (-not $PSBoundParameters.ContainsKey('GrantReadOnly')) {
            $GrantReadOnly = $false
        }

        if (-not $PSBoundParameters.ContainsKey('GridView')) {
            $GridView = $false
        }
    }
    process {
        if ($GrantReadOnly -eq $true) {
            if ($ReadOnlyGroup -eq '') {
                throw 'ReadOnlyGroup value missing'
            }
            elseif ($ReadOnlyGroup -ne '') {
                $readonlygroup_exists = Invoke-PGSqlQuery -Type Select -Query "select * from pg_group where groname = '$ReadOnlyGroup'"
                if ($null -eq $readonlygroup_exists) {
                    $errormessage = @"

Postgresql Group "$ReadOnlyGroup" is missing and needs to be created.
Create statement:

    CREATE ROLE readonly WITH
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    INHERIT
    NOREPLICATION
    NOBYPASSRLS
    CONNECTION LIMIT -1;

"@
                    Write-Error -Message $errormessage
                    break
                }
            }
        }

        $definitions = $InputObject[0] | Get-Member | Where-Object { $_.membertype -in ('Property', 'NoteProperty') } | Select-Object @{name = 'Property'; expression = { $_.name.trim() -replace '(\(|\)|\%)', '' -replace '( |/|-)', '_' } }, @{name = 'DataType'; expression = { $_.definition.split(' ')[0] } }

        $types = @(
            'int',                                        
            'string',                                     
            'bool',
            'System.Boolean',                                     
            'System.Management.Automation.PSCustomObject',
            'object',                                     
            'Object[]',
            'System.Object[]',                                   
            'guid',                                       
            'datetime',                                   
            'decimal',                                    
            'long',                                       
            'single',                                     
            'double',
            'System.String',
            'System.Int32',
            'System.Int64',
            'System.DateTime',
            'ipaddress',
            'uint32',
            'byte',
            'System.Net.IPAddress',
            'System.Double',
            'short',
            'string[]'                                 
        )
        $missingtypes = @()

        foreach ($field in $definitions) {
            if ($field.DataType -notin $types) {
                $missingtypes += $field
            }
        }
        if ($missingtypes) {
            Write-Host -ForegroundColor Red 'Your data contains unsupported types, they may need to be added to $types'
            Write-Host $missingtypes
            break
        }
  
        if ($GridView -eq $true) {
            $data | Out-GridView -Wait
            $msg = 'Do you want to continue? [Y/N]'
            $response = Read-Host -Prompt $msg
            if ($response -eq 'n') { break }
        }

        #$tabledata = Set-PGTableProperties -Object $InputObject -TableName $Table -SchemaName $Schema -PrimaryKeys $PrimaryKeys
        $tableData = Set-PGTablePropertiesAdvanced -Object $InputObject -TableName $Table -SchemaName $Schema -PrimaryKeys $PrimaryKeys
        $fields = $tabledata.Fields
        $pkey = $tabledata.PKey
        $tablename = $tabledata.TableName
        $schemaname = $tabledata.SchemaName


        if ($pkey.count -lt 1 -or $null -eq $pkey) {
            Write-Error "WARNING: You didn't select any primary keys"
            return
        }

     
        $keywordspattern = "($($($sqlkeywords -replace '^.{0}','^' -replace '.{0}$','$') -join '|'))"

        $pght = @{}
        $pgfields = $fields | Select-Object @{name = 'Name'; expression = { $_.Name.ToLower() -replace $keywordspattern, '"$1"' } }, Value
        $pgfields | ForEach-Object { $pght[$_.Name] = $_.value }

        $pgdefinitions = $definitions | Select-Object @{name = 'property'; expression = { $_.Property.ToLower() -replace $keywordspattern, '"$1"' } }, datatype
        $pgdefinitions = $pgdefinitions | Select-Object property, datatype, @{name = 'PGType'; expression = { $pght["$($_.Property)"] } }
        $pgcolumns = $pgdefinitions | Where-Object { $_.Property -in $pgfields.name }
        $pkey = $pkey.ToLower() -replace $keywordspattern, '"$1"'


        $pkey_value = $pkey -join ','
        $pkey_name = $tablename + '_pkey'

        $columns = foreach ($column in $pgcolumns) {
            if ($column.property -in $pkey) { "$($column.Property) $($column.PgType) NOT NULL," }else { "$($column.Property) $($column.PgType)," }
        }

         
        $createschema = if ($schemaname -cmatch '[A-Z]') { "`"$schemaname`"" } else { $schemaname }
   
        
        $createtablestatement = @"
CREATE TABLE $createschema.$tablename
(
$columns
CONSTRAINT $pkey_name PRIMARY KEY ($($pkey_value))
)
"@


        $tableexists = Invoke-PGSQLSelect -Query "SELECT * from information_schema.tables WHERE table_schema = '$schemaname' and table_name = '$tablename'" 

        if ($tableexists) {
            Write-Host "$createschema.$tablename - Already Exists" -ForegroundColor Red
            break
        }



        Invoke-PGSQLSelect -Query $createtablestatement
        Write-Host -Object $createtablestatement -ForegroundColor Blue
        
        $tablecreated = Invoke-PGSQLSelect -Query "SELECT * from information_schema.tables WHERE table_schema = '$schemaname' and table_name = '$tablename'" 
        if ($tablecreated) {
            Write-Host "$createschema.$tablename - Created Successfully" -ForegroundColor Green
        
            if ($GrantReadOnly) {
                Invoke-PGSQLSelect -Query "grant select on $createschema.$tablename to $ReadOnlyGroup;"
                Write-Host "$createschema.$tablename - Granted Select to `"$ReadOnlyGroup`"" -ForegroundColor Green
            }
        }
 

    }
    end {
        Get-PGSQLTableDefinitions -Force
        Disconnect-PGSQLServer
    }
    
}


Function Write-PGSQLLog {

    <#
.SYNOPSIS
    Writes a log to a Postgresql DB
.DESCRIPTION
    Writes a log in a format similar to CMTrace to public.powershell_log, useful for tracking scripts and an alternative to using Transcript
.EXAMPLE

    Write an informational log from the current function

    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    
#>



    [CmdletBinding()]
    Param( 

        #The source log
        [parameter(Mandatory = $True)]
        [String]$Log,
    
        #The information to log
        [parameter(Mandatory = $True)]
        [String]$Value,
    
        #The source of the error
        [parameter(Mandatory = $True)]
        [String]$Component,
    
        #The severity (1 - Information, 2- Warning, 3 - Error)
        [parameter(Mandatory = $True)]
        [ValidateSet(1, 2, 3)]
        [int]$Severity,

        [parameter(Mandatory = $False)]
        [String]$Schedule = 'Manual'
    )

    begin {
        Connect-PGSQLServer
    }
    process {
        $SeverityTable = @{
            1 = 'Information'
            2 = 'Warning'
            3 = 'Error'
        }

        $record = [PSCustomObject]@{
            timestamp = $(Get-Date).ToUniversalTime()
            log       = $PSBoundParameters['Log']
            component = $PSBoundParameters['Component']
            value     = $PSBoundParameters['Value']
            context   = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
            severity  = $SeverityTable.Item($PSBoundParameters['Severity'])
            pid       = $pid
            schedule  = $schedule
        }
        Invoke-PGSqlQuery -Type Insert -InputObject $record -OnConflict 'Do Nothing' -Schema 'public' -Table 'powershell_log' -Truncate $false
    }
    end {
        Disconnect-PGSQLServer
    }

}
Function Get-PGSQLInsertLog {
    Remove-Item -Path .\insert_query.sql -Force -Confirm:$false -ErrorAction SilentlyContinue
    $PgInsertQuery > insert_query.sql
    code insert_query.sql
}

Function Invoke-PGSqlQuery {
    param (
        [Parameter(Position = 0)]
        [ValidateSet('Select', 'Insert', 'Truncate')]
        [string]
        $Type
    )
    DynamicParam {
        if ($Type -eq 'Select') {
            $SelectAttribute = New-Object System.Management.Automation.ParameterAttribute
            $SelectAttribute.Mandatory = $true
            $SelectAttribute.HelpMessage = 'Enter a select statement:'
            $SelectAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $SelectAttributeCollection.Add($SelectAttribute)
            $SelectAttributeCollection.Add((New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute))
            $SelectParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Query', [string], $SelectAttributeCollection)
            $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('Query', $SelectParam)
            return $paramDictionary
        }
        if ($Type -eq 'Insert') {
            
            $InputObjectAttribute = New-Object System.Management.Automation.ParameterAttribute
            $InputObjectAttribute.Mandatory = $true
            $InputObjectAttribute.HelpMessage = 'Enter the InputObject:'
            $InputObjectAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $InputObjectAttributeCollection.Add($InputObjectAttribute)
            $InputObjectAttributeCollection.Add((New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute))
            $InputObjectParam = New-Object System.Management.Automation.RuntimeDefinedParameter('InputObject', [System.Object], $InputObjectAttributeCollection)

            $SchemaAttribute = New-Object System.Management.Automation.ParameterAttribute
            $SchemaAttribute.Mandatory = $true
            $SchemaAttribute.HelpMessage = 'Enter the schema name:'
            $SchemaAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $SchemaAttributeCollection.Add($SchemaAttribute)
            $SchemaParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Schema', [string], $SchemaAttributeCollection)

            $TableAttribute = New-Object System.Management.Automation.ParameterAttribute
            $TableAttribute.Mandatory = $true
            $TableAttribute.HelpMessage = 'Enter the table name:'
            $TableAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $TableAttributeCollection.Add($TableAttribute)
            $TableParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Table', [string], $TableAttributeCollection)

            $OnConflictValidateArray = @('Do Nothing', 'Set Excluded', 'null')
            $OnConflictAttribute = New-Object System.Management.Automation.ParameterAttribute
            $OnConflictAttribute.Mandatory = $true
            $OnConflictAttribute.HelpMessage = 'Enter the conflict statement:'
            $OnConflictAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $OnConflictAttributeCollection.Add($OnConflictAttribute)
            $OnConflictAttributeCollection.Add((New-Object System.Management.Automation.ValidateSetAttribute($OnConflictValidateArray)))
            $OnConflictParam = New-Object System.Management.Automation.RuntimeDefinedParameter('OnConflict', [string], $OnConflictAttributeCollection)

            $TruncateTableAttribute = New-Object System.Management.Automation.ParameterAttribute
            $TruncateTableAttribute.Mandatory = $true
            $TruncateTableAttribute.HelpMessage = 'Truncate table?:'
            $TruncateTableAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $TruncateTableAttributeCollection.Add($TruncateTableAttribute)
            $TruncateTableParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Truncate', [bool], $TruncateTableAttributeCollection)

            $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('InputObject', $InputObjectParam)
            $paramDictionary.Add('Schema', $SchemaParam)
            $paramDictionary.Add('Table', $TableParam)
            $paramDictionary.Add('OnConflict', $OnConflictParam)
            $paramDictionary.Add('Truncate', $TruncateTableParam)
         
            return $paramDictionary
        }
        if ($Type -eq 'Truncate') {
             
            $SchemaAttribute = New-Object System.Management.Automation.ParameterAttribute
            $SchemaAttribute.Mandatory = $true
            $SchemaAttribute.HelpMessage = 'Enter the schema name:'
            $SchemaAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $SchemaAttributeCollection.Add($SchemaAttribute)
            $SchemaAttributeCollection.Add((New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute))
            $SchemaParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Schema', [string], $SchemaAttributeCollection)

            $TableAttribute = New-Object System.Management.Automation.ParameterAttribute
            $TableAttribute.Mandatory = $true
            $TableAttribute.HelpMessage = 'Enter the table name:'
            $TableAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $TableAttributeCollection.Add($TableAttribute)
            $TableAttributeCollection.Add((New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute))
            $TableParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Table', [string], $TableAttributeCollection)
 
            $TruncateTableAttribute = New-Object System.Management.Automation.ParameterAttribute
            $TruncateTableAttribute.Mandatory = $true
            $TruncateTableAttribute.HelpMessage = 'Truncate table?:'
            $TruncateTableAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $TruncateTableAttributeCollection.Add($TruncateTableAttribute)
            $TruncateTableParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Truncate', [bool], $TruncateTableAttributeCollection)

            $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('Schema', $SchemaParam)
            $paramDictionary.Add('Table', $TableParam)
            $paramDictionary.Add('Truncate', $TruncateTableParam)

            return $paramDictionary
        }
    }

    begin {
        Connect-PGSQLServer
    }


    process {
        switch ($Type) {
            'Select' { 
                Invoke-PGSQLSelect -Query $PsBoundParameters.Query
                break
            }
            'Insert' { 
                Invoke-PGSQLInsert -InputObject $PsBoundParameters.InputObject -OnConflict $PsBoundParameters.OnConflict -Schema $PsBoundParameters.Schema -Table $PsBoundParameters.Table -Truncate $PsBoundParameters.Truncate
                break
            }
            'Truncate' {
                if ($PsBoundParameters.Truncate -eq $true) {
                    Invoke-PGSQLTruncate -Schema $PsBoundParameters.Schema -Table $PsBoundParameters.Table
                }
                else { Write-Host 'TruncateTable not true' }
                break
            }
        }
    }
    end {
        Disconnect-PGSQLServer
    }
}

function Set-PGTableProperties {
    <#
    .SYNOPSIS
        Interactive GUI for selecting table name, schema, columns, types, and primary keys.
    .DESCRIPTION
        Lets the user select which properties to include as columns, their types, and which are primary keys.
    .PARAMETER Object
        The input object (array of PSCustomObject) to analyze.
    .PARAMETER TableName
        Optional default table name.
    .PARAMETER SchemaName
        Optional default schema name.
    .PARAMETER PrimaryKeys
        Optional array of default primary key names.
    .OUTPUTS
        [PSCustomObject] with Fields, PKey, TableName, SchemaName
    #>
    param (
        [Parameter(Mandatory = $true)]
        $Object,
        [string]$TableName,
        [string]$SchemaName,
        [array]$PrimaryKeys
    )

    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')

    $form = New-Object Windows.Forms.Form
    $form.Text = 'PostgreSQL Table Designer'
    $form.Size = [Drawing.Size]::new(900, 650)
    $form.MinimumSize = [Drawing.Size]::new(900, 650)
    $form.MaximizeBox = $false
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object Drawing.Font('Segoe UI', 10)

    $toolTip = New-Object System.Windows.Forms.ToolTip

    # Header
    $lblHeader = New-Object Windows.Forms.Label
    $lblHeader.Text = 'PostgreSQL Table Designer'
    $lblHeader.Font = New-Object Drawing.Font('Segoe UI', 16, [Drawing.FontStyle]::Bold)
    $lblHeader.AutoSize = $true
    $lblHeader.Location = [Drawing.Point]::new(20, 10)
    $form.Controls.Add($lblHeader)

    # Table Name
    $lblTable = New-Object Windows.Forms.Label
    $lblTable.Text = 'Table Name:'
    $lblTable.Location = [Drawing.Point]::new(20, 55)
    $lblTable.AutoSize = $true
    $form.Controls.Add($lblTable)

    $txtTable = New-Object Windows.Forms.TextBox
    $txtTable.Location = [Drawing.Point]::new(120, 52)
    $txtTable.Size = [Drawing.Size]::new(200, 28)
    if ($TableName) { $txtTable.Text = $TableName }
    $form.Controls.Add($txtTable)
    $toolTip.SetToolTip($txtTable, 'Enter the name for the new table.')

    # Schema Name
    $lblSchema = New-Object Windows.Forms.Label
    $lblSchema.Text = 'Schema Name:'
    $lblSchema.Location = [Drawing.Point]::new(350, 55)
    $lblSchema.AutoSize = $true
    $form.Controls.Add($lblSchema)

    $cmbSchema = New-Object Windows.Forms.ComboBox
    $cmbSchema.Location = [Drawing.Point]::new(460, 52)
    $cmbSchema.Size = [Drawing.Size]::new(200, 28)
    $cmbSchema.DropDownStyle = 'DropDown'
    $schemas = (Invoke-PGSQLSelect -Query "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT LIKE '%timescaledb_%'").schema_name | Sort-Object
    $cmbSchema.Items.AddRange($schemas)
    if ($SchemaName) { $cmbSchema.SelectedItem = $SchemaName }
    $form.Controls.Add($cmbSchema)
    $toolTip.SetToolTip($cmbSchema, 'Select the schema for the new table.')

    # GroupBox for Columns
    $gbColumns = New-Object Windows.Forms.GroupBox
    $gbColumns.Text = 'Columns (check to include, select type)'
    $gbColumns.Location = [Drawing.Point]::new(20, 100)
    $gbColumns.Size = [Drawing.Size]::new(400, 420)
    $form.Controls.Add($gbColumns)

    $clbColumns = New-Object Windows.Forms.CheckedListBox
    $clbColumns.Location = [Drawing.Point]::new(10, 25)
    $clbColumns.Size = [Drawing.Size]::new(170, 370)
    $clbColumns.CheckOnClick = $true
    $gbColumns.Controls.Add($clbColumns)

    # Data type combos for each property
    $typeMap = @{
        'int' = 'integer'; 'string' = 'text'; 'bool' = 'boolean'; 'System.Boolean' = 'boolean'
        'System.Management.Automation.PSCustomObject' = 'jsonb'; 'object' = 'text'
        'Object[]' = 'jsonb'; 'System.Object[]' = 'jsonb'; 'guid' = 'uuid'; 'datetime' = 'timestamp'
        'decimal' = 'double precision'; 'long' = 'bigint'; 'single' = 'double precision'
        'System.String' = 'text'; 'double' = 'double precision'; 'System.Int32' = 'integer'
        'System.DateTime' = 'timestamp'; 'ipaddress' = 'inet'; 'uint32' = 'bigint'
        'System.Int64' = 'bigint'; 'System.Decimal' = 'numeric'; 'byte' = 'integer'
        'System.Net.IPAddress' = 'inet'; 'System.Double' = 'double precision'
        'macaddress' = 'macaddr'; 'string[]' = 'text'
    }
    $typeOptions = $typeMap.Values | Select-Object -Unique

    $properties = $Object[0] | Get-Member | Where-Object { $_.MemberType -in 'Property', 'NoteProperty' } |
    Select-Object @{n = 'Property'; e = { $_.Name.Trim() -replace '(\(|\)|\%)', '' -replace '( |/|-)', '_' } },
    @{n = 'DataType'; e = { $_.Definition.Split(' ')[0] } }

    $comboBoxes = @{}
    $y = 25
    foreach ($prop in $properties) {
        $clbColumns.Items.Add($prop.Property, $true) | Out-Null
        $combo = New-Object Windows.Forms.ComboBox
        $combo.Location = [Drawing.Point]::new(190, $y)
        $combo.Size = [Drawing.Size]::new(180, 24)
        $combo.DropDownStyle = 'DropDownList'
        $combo.Items.AddRange($typeOptions)
        $defaultType = $typeMap[$prop.DataType]
        if ($defaultType) { $combo.SelectedItem = $defaultType } else { $combo.SelectedIndex = 0 }
        $gbColumns.Controls.Add($combo)
        $comboBoxes[$prop.Property] = $combo
        $y += 28
    }
    $toolTip.SetToolTip($clbColumns, 'Check columns to include in the table. Use the dropdown to select the data type.')

    # GroupBox for Primary Keys
    $gbPK = New-Object Windows.Forms.GroupBox
    $gbPK.Text = 'Primary Keys (check one or more)'
    $gbPK.Location = [Drawing.Point]::new(440, 100)
    $gbPK.Size = [Drawing.Size]::new(250, 420)
    $form.Controls.Add($gbPK)

    $clbPK = New-Object Windows.Forms.CheckedListBox
    $clbPK.Location = [Drawing.Point]::new(10, 25)
    $clbPK.Size = [Drawing.Size]::new(220, 370)
    $clbPK.CheckOnClick = $true
    foreach ($prop in $properties) {
        $isChecked = $PrimaryKeys -and ($prop.Property -in $PrimaryKeys)
        $clbPK.Items.Add($prop.Property, $isChecked) | Out-Null
    }
    $gbPK.Controls.Add($clbPK)
    $toolTip.SetToolTip($clbPK, 'Check one or more columns to use as the primary key.')

    # OK/Cancel buttons
    $btnOK = New-Object Windows.Forms.Button
    $btnOK.Text = 'OK'
    $btnOK.Size = [Drawing.Size]::new(100, 36)
    $btnOK.Location = [Drawing.Point]::new(720, 500)
    $btnOK.Font = New-Object Drawing.Font('Segoe UI', 11, [Drawing.FontStyle]::Bold)
    $btnOK.BackColor = [Drawing.Color]::FromArgb(0, 120, 215)
    $btnOK.ForeColor = [Drawing.Color]::White
    $btnOK.FlatStyle = 'Flat'
    $btnOK.Add_Click({
            $form.DialogResult = [Windows.Forms.DialogResult]::OK
            $form.Close()
        })
    $form.Controls.Add($btnOK)

    $btnCancel = New-Object Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Size = [Drawing.Size]::new(100, 36)
    $btnCancel.Location = [Drawing.Point]::new(720, 550)
    $btnCancel.Font = New-Object Drawing.Font('Segoe UI', 11, [Drawing.FontStyle]::Bold)
    $btnCancel.BackColor = [Drawing.Color]::FromArgb(232, 17, 35)
    $btnCancel.ForeColor = [Drawing.Color]::White
    $btnCancel.FlatStyle = 'Flat'
    $btnCancel.Add_Click({
            $form.DialogResult = [Windows.Forms.DialogResult]::Cancel
            $form.Close()
        })
    $form.Controls.Add($btnCancel)

    # Show dialog
    $result = $form.ShowDialog()
    if ($result -eq [Windows.Forms.DialogResult]::Cancel) {
        Write-Host 'Cancelled by user.'
        return $null
    }

    # Gather selections
    $fields = @()
    for ($i = 0; $i -lt $clbColumns.Items.Count; $i++) {
        if ($clbColumns.GetItemChecked($i)) {
            $name = $clbColumns.Items[$i]
            $fields += [PSCustomObject]@{
                Name  = $name
                Value = $comboBoxes[$name].SelectedItem
            }
        }
    }
    $pkey = @()
    for ($i = 0; $i -lt $clbPK.Items.Count; $i++) {
        if ($clbPK.GetItemChecked($i)) {
            $pkey += $clbPK.Items[$i]
        }
    }

    [PSCustomObject]@{
        Fields     = $fields
        PKey       = $pkey
        TableName  = $txtTable.Text
        SchemaName = $cmbSchema.Text
    }
}

function Set-PGTablePropertiesAdvanced {
    <#
    .SYNOPSIS
        Advanced GUI for selecting table name, schema, columns, types, constraints, and primary keys.
    .DESCRIPTION
        Lets the user select which properties to include as columns, their types, constraints, and which are primary keys.
    .OUTPUTS
        [PSCustomObject] with Fields, PKey, TableName, SchemaName, PreviewSQL
    #>
    param (
        [Parameter(Mandatory = $true)]
        $Object,
        [string]$TableName,
        [string]$SchemaName,
        [array]$PrimaryKeys
    )

    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')

    $form = New-Object Windows.Forms.Form
    $form.Text = 'PostgreSQL Table Designer'
    $form.Size = [Drawing.Size]::new(900, 800)
    $form.MinimumSize = [Drawing.Size]::new(900, 800)
    $form.MaximizeBox = $false
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object Drawing.Font('Segoe UI', 10)

    $toolTip = New-Object System.Windows.Forms.ToolTip

    # Header
    $lblHeader = New-Object Windows.Forms.Label
    $lblHeader.Text = 'PostgreSQL Table Designer'
    $lblHeader.Font = New-Object Drawing.Font('Segoe UI', 16, [Drawing.FontStyle]::Bold)
    $lblHeader.AutoSize = $true
    $lblHeader.Location = [Drawing.Point]::new(20, 10)
    $form.Controls.Add($lblHeader)

    # Schema Name (now on the left)
    $lblSchema = New-Object Windows.Forms.Label
    $lblSchema.Text = 'Schema Name:'
    $lblSchema.Location = [Drawing.Point]::new(20, 55)
    $lblSchema.AutoSize = $true
    $form.Controls.Add($lblSchema)

    $cmbSchema = New-Object Windows.Forms.ComboBox
    $cmbSchema.Location = [Drawing.Point]::new(120, 52)
    $cmbSchema.Size = [Drawing.Size]::new(200, 28)
    $cmbSchema.DropDownStyle = 'DropDown'
    $schemas = (Invoke-PGSQLSelect -Query "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT LIKE '%timescaledb_%'").schema_name | Sort-Object
    $cmbSchema.Items.AddRange($schemas)
    if ($SchemaName) { $cmbSchema.SelectedItem = $SchemaName }
    $form.Controls.Add($cmbSchema)
    $toolTip.SetToolTip($cmbSchema, 'Select the schema for the new table.')

    # Table Name (now on the right)
    $lblTable = New-Object Windows.Forms.Label
    $lblTable.Text = 'Table Name:'
    $lblTable.Location = [Drawing.Point]::new(350, 55)
    $lblTable.AutoSize = $true
    $form.Controls.Add($lblTable)

    $txtTable = New-Object Windows.Forms.TextBox
    $txtTable.Location = [Drawing.Point]::new(460, 52)
    $txtTable.Size = [Drawing.Size]::new(200, 28)
    if ($TableName) { $txtTable.Text = $TableName }
    $form.Controls.Add($txtTable)
    $toolTip.SetToolTip($txtTable, 'Enter the name for the new table.')

    # GroupBox for Columns (integrated per-row layout)
    $gbColumns = New-Object Windows.Forms.GroupBox
    $gbColumns.Text = 'Columns (select column to include, type, constraints, default value)'
    $gbColumns.Location = [Drawing.Point]::new(20, 100)
    $form.Controls.Add($gbColumns)

    $typeMap = @{
        'int' = 'integer'; 'string' = 'text'; 'bool' = 'boolean'; 'System.Boolean' = 'boolean'
        'System.Management.Automation.PSCustomObject' = 'jsonb'; 'object' = 'text'
        'Object[]' = 'jsonb'; 'System.Object[]' = 'jsonb'; 'guid' = 'uuid'; 'datetime' = 'timestamp'
        'decimal' = 'double precision'; 'long' = 'bigint'; 'single' = 'double precision'
        'System.String' = 'text'; 'double' = 'double precision'; 'System.Int32' = 'integer'
        'System.DateTime' = 'timestamp'; 'ipaddress' = 'inet'; 'uint32' = 'bigint'
        'System.Int64' = 'bigint'; 'System.Decimal' = 'numeric'; 'byte' = 'integer'
        'System.Net.IPAddress' = 'inet'; 'System.Double' = 'double precision'
        'macaddress' = 'macaddr'; 'string[]' = 'text'
    }
    $typeOptions = $typeMap.Values | Select-Object -Unique

    $properties = $Object[0] | Get-Member | Where-Object { $_.MemberType -in 'Property', 'NoteProperty' } |
    Select-Object @{n = 'Property'; e = { $_.Name.Trim() -replace '(\(|\)|\%)', '' -replace '( |/|-)', '_' } },
    @{n = 'DataType'; e = { $_.Definition.Split(' ')[0] } }

    $rowControls = @{}
    $rowHeight = 28
    $headerFont = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)
    # Add header row (now with 'Include' checkbox column)
    $x0 = 10
    $y = 25
    $headers = @('Include', 'Column', 'Type', 'Primary Key', 'NOT NULL', 'Default Value')
    $widths = @(60, 150, 120, 100, 90, 180)
    $x = $x0
    for ($i = 0; $i -lt $headers.Count; $i++) {
        $lbl = New-Object Windows.Forms.Label
        $lbl.Text = $headers[$i]
        $lbl.Location = [Drawing.Point]::new($x, $y)
        $lbl.Size = [Drawing.Size]::new($widths[$i], 24)
        $lbl.Font = $headerFont
        $gbColumns.Controls.Add($lbl)
        $x += $widths[$i]
    }
    $y += $rowHeight

    foreach ($prop in $properties) {
        $x = $x0
        $row = @{}
        # Include checkbox
        $chkInclude = New-Object Windows.Forms.CheckBox
        $chkInclude.Text = ''
        $chkInclude.Checked = $true
        # Place checkbox with a little padding, but not so much that it cuts off the label
        $chkInclude.Location = [Drawing.Point]::new($x + 5, $y)
        $chkInclude.Size = [Drawing.Size]::new($widths[0] - 10, 24)
        $gbColumns.Controls.Add($chkInclude)
        $row.Include = $chkInclude
        $x += $widths[0]

        # Property label
        $lbl = New-Object Windows.Forms.Label
        $lbl.Text = $prop.Property
        # Place label with a little padding from the left edge of its cell
        $lbl.Location = [Drawing.Point]::new($x + 2, $y)
        $lbl.Size = [Drawing.Size]::new($widths[1] - 4, 24)
        $gbColumns.Controls.Add($lbl)
        $x += $widths[1]

        # Type ComboBox
        $combo = New-Object Windows.Forms.ComboBox
        $combo.Location = [Drawing.Point]::new($x, $y)
        $combo.Size = [Drawing.Size]::new($widths[2], 24)
        $combo.DropDownStyle = 'DropDownList'
        $combo.Items.AddRange($typeOptions)
        $defaultType = $typeMap[$prop.DataType]
        if ($defaultType) { $combo.SelectedItem = $defaultType } else { $combo.SelectedIndex = 0 }
        $gbColumns.Controls.Add($combo)
        $row.ComboBox = $combo
        $x += $widths[2]


        # PK checkbox
        $chkPK = New-Object Windows.Forms.CheckBox
        $chkPK.Text = ''
        $chkPK.Location = [Drawing.Point]::new($x + 30, $y)
        $chkPK.Size = [Drawing.Size]::new($widths[3], 24)
        if ($PrimaryKeys -and ($prop.Property -in $PrimaryKeys)) { $chkPK.Checked = $true }
        $gbColumns.Controls.Add($chkPK)
        $row.PK = $chkPK
        $x += $widths[3]

        # NOT NULL checkbox
        $chkNotNull = New-Object Windows.Forms.CheckBox
        $chkNotNull.Text = ''
        $chkNotNull.Location = [Drawing.Point]::new($x + 30, $y)
        $chkNotNull.Size = [Drawing.Size]::new($widths[4], 24)
        $gbColumns.Controls.Add($chkNotNull)
        $row.NotNull = $chkNotNull
        $x += $widths[4]

        # Default value TextBox
        $txtDefault = New-Object Windows.Forms.TextBox
        $txtDefault.Location = [Drawing.Point]::new($x + 30, $y)
        $txtDefault.Size = [Drawing.Size]::new($widths[5], 24)
        $gbColumns.Controls.Add($txtDefault)
        $row.Default = $txtDefault

        $rowControls[$prop.Property] = $row
        $y += $rowHeight
    }
    $gbColumns.Size = [Drawing.Size]::new(840, $y + 20)
    $toolTip.SetToolTip($gbColumns, 'Check Include to add column. Set type, NOT NULL, Primary Key, and default value for each column.')

    # SQL Preview
    $gbPreview = New-Object Windows.Forms.GroupBox
    $gbPreview.Text = 'CREATE TABLE Preview'
    $gbPreview.Location = [Drawing.Point]::new(20, 540)
    $gbPreview.Size = [Drawing.Size]::new(840, 150)
    $gbPreview.Anchor = 'Left,Right,Bottom'
    $form.Controls.Add($gbPreview)

    $txtPreview = New-Object Windows.Forms.TextBox
    $txtPreview.Location = [Drawing.Point]::new(10, 25)
    $txtPreview.Size = [Drawing.Size]::new(800, 110)
    $txtPreview.Multiline = $true
    $txtPreview.ReadOnly = $true
    $txtPreview.ScrollBars = 'Vertical'
    $txtPreview.Anchor = 'Top,Left,Right,Bottom'
    $gbPreview.Controls.Add($txtPreview)

    function Update-Preview {
        $fields = @()
        $pkey = @()
        foreach ($name in $rowControls.Keys) {
            $row = $rowControls[$name]
            if (-not $row.Include.Checked) { continue }
            $type = $row.ComboBox.SelectedItem
            $notnull = $row.NotNull.Checked
            $isPK = $row.PK.Checked
            $defval = $row.Default.Text
            $col = "$name $type"
            if ($notnull) { $col += ' NOT NULL' }
            if ($defval -and $defval -ne '') { $col += " DEFAULT '$defval'" }
            $fields += $col
            if ($isPK) { $pkey += $name }
        }
        $tablename = $txtTable.Text
        $schemaname = $cmbSchema.Text
        $pkeystr = if ($pkey -and $pkey.Count -gt 0) { "CONSTRAINT ${tablename}_pkey PRIMARY KEY (" + ($pkey -join ', ') + ')' } else { '' }
        $cols = $fields -join ",`r`n"
        $sql = "CREATE TABLE $schemaname.$tablename (`r`n$cols"
        if ($pkeystr) { $sql += ",`r`n$pkeystr" }
        $sql += "`r`n);"
        $txtPreview.Text = $sql
    }

    # Wire up events for all controls
    foreach ($row in $rowControls.Values) {
        $row.Include.Add_CheckedChanged({ Update-Preview; Validate-Form })
        $row.ComboBox.Add_SelectedIndexChanged({ Update-Preview })
        $row.NotNull.Add_CheckedChanged({ Update-Preview })
        $row.PK.Add_CheckedChanged({
            $thisRow = $null
            foreach ($key in $rowControls.Keys) {
                if ($rowControls[$key].PK -eq $this) { $thisRow = $rowControls[$key]; break }
            }
            if ($null -ne $thisRow -and $this.Checked) {
                $thisRow.NotNull.Checked = $true
            }
            Update-Preview
            Validate-Form
        })
        $row.Default.Add_TextChanged({ Update-Preview })
    }
    $txtTable.Add_TextChanged({ Update-Preview })
    $cmbSchema.Add_SelectedIndexChanged({ Update-Preview })

    # OK/Cancel buttons
    $btnOK = New-Object Windows.Forms.Button
    $btnOK.Text = 'OK'
    $btnOK.Size = [Drawing.Size]::new(120, 40)
    $btnOK.FlatStyle = 'System'
    $btnOK.Location = [Drawing.Point]::new($form.ClientSize.Width - 260, $form.ClientSize.Height - 70)
    $btnOK.Anchor = 'Bottom,Right'
    $form.Controls.Add($btnOK)

    $btnCancel = New-Object Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Size = [Drawing.Size]::new(120, 40)
    $btnCancel.FlatStyle = 'System'
    $btnCancel.Location = [Drawing.Point]::new($form.ClientSize.Width - 130, $form.ClientSize.Height - 70)
    $btnCancel.Anchor = 'Bottom,Right'
    $form.Controls.Add($btnCancel)

    # Validation
    function Validate-Form {
        $ok = $true
        if (-not $txtTable.Text -or -not $cmbSchema.Text) { $ok = $false }
        $checkedCols = 0
        $checkedPK = 0
        foreach ($name in $rowControls.Keys) {
            $row = $rowControls[$name]
            if ($row.Include.Checked) {
                $checkedCols++
                if ($row.PK.Checked) { $checkedPK++ }
            }
        }
        if ($checkedCols -lt 1) { $ok = $false }
        if ($checkedPK -lt 1) { $ok = $false }
        $btnOK.Enabled = $ok
    }

    $txtTable.Add_TextChanged({ Validate-Form })
    $cmbSchema.Add_SelectedIndexChanged({ Validate-Form })
    foreach ($row in $rowControls.Values) { $row.PK.Add_CheckedChanged({ Validate-Form }) }

    # Keyboard shortcuts
    $form.KeyPreview = $true
    $form.Add_KeyDown({
            if ($_.KeyCode -eq 'Enter' -and $btnOK.Enabled) { $btnOK.PerformClick() }
            if ($_.KeyCode -eq 'Escape') { $btnCancel.PerformClick() }
        })

    # Button events
    $btnOK.Add_Click({
            if (-not $btnOK.Enabled) {
                [System.Windows.Forms.MessageBox]::Show('Please fill all required fields and select at least one column and primary key.', 'Validation Error', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }
            $form.DialogResult = [Windows.Forms.DialogResult]::OK
            $form.Close()
        })
    $btnCancel.Add_Click({
            $form.DialogResult = [Windows.Forms.DialogResult]::Cancel
            $form.Close()
        })

    # Initial preview and validation
    Update-Preview
    Validate-Form

    # Show dialog
    $result = $form.ShowDialog()
    if ($result -eq [Windows.Forms.DialogResult]::Cancel) {
        return $null
    }

    # Gather selections
    $fields = @()
    $pkey = @()
    foreach ($name in $rowControls.Keys) {
        $row = $rowControls[$name]
        if (-not $row.Include.Checked) { continue }
        $fields += [PSCustomObject]@{
            Name    = $name
            Type    = $row.ComboBox.SelectedItem
            NotNull = $row.NotNull.Checked
            Default = $row.Default.Text
        }
        if ($row.PK.Checked) { $pkey += $name }
    }

    [PSCustomObject]@{
        Fields     = $fields
        PKey       = $pkey
        TableName  = $txtTable.Text
        SchemaName = $cmbSchema.Text
        PreviewSQL = $txtPreview.Text
    }
}