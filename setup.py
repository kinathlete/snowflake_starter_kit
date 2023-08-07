import os
import pandas as pd
from snowflake.snowpark import Session



# INITIATE THE SNOWFLAKE SESSION #
def initiate_sf_session(role):

    connection_parameters = {
        "account": os.getenv("SF_ACC"),
        "user": os.getenv("SF_USER"),
        "password": os.getenv("SF_PW"),
        "role": role
        }
    session = Session.builder.configs(connection_parameters).create()
    
    return session 

# READ SNOWFLAKE SETUP DATA FROM DATA FOLDER
def read_setup_data(filename):

    absolute_path = os.path.dirname(__file__)
    rel_path_to_data = "data/{}.csv".format(filename)
    full_path_to_data = os.path.join(absolute_path, rel_path_to_data)
    df = pd.read_csv(full_path_to_data, dtype="str")

    return df

def switch_role(session, role):
    session.sql(f"use role {role}")
    return f"Switched to role: {role}"

### SECURITY INTEGRATION ###

# 1 EXTRACT VARIABLES FROM DATA
auth_df = read_setup_data("auth_data")
auth_params = dict(zip(auth_df.Variable, auth_df.Value))

# 2 EXECUTE SECURITY INTEGRATION STATEMENT
print("1 CREATING SECURITY INTEGRATION")
session = initiate_sf_session("accountadmin")
session.sql("""create or replace security integration {0}
    type = {1}
    enabled = {2}
    saml2_issuer = '{3}'
    saml2_sso_url = '{4}'
    saml2_provider = '{5}'
    saml2_x509_cert = '{6}'
    saml2_sp_initiated_login_page_label = '{7}'
    saml2_enable_sp_initiated = {8}
    SAML2_SNOWFLAKE_ACS_URL = '{9}'
    SAML2_SNOWFLAKE_ISSUER_URL = '{10}'""".format(auth_params['NAME'], auth_params['TYPE'], auth_params['ENABLED'], auth_params['SAML2_ISSUER']\
                                                 , auth_params['SAML2_SSO_URL'], auth_params['SAML2_PROVIDER'], auth_params['SAML2_X509_CERT']\
                                                    , auth_params['SAML2_SP_INITIATED_LOGIN_PAGE_LABEL'], auth_params['SAML2_ENABLE_SP_INITIATED']\
                                                        , auth_params['SAML2_SNOWFLAKE_ACS_URL'], auth_params['SAML2_SNOWFLAKE_ISSUER_URL'])).collect()
# 3 CLOSE SF SESSION #
session.close()

### ROLES ###

# 1 GET ROLES FROM DATA #
roles_df = read_setup_data("roles_data")

# 2 EXECUTE ROLE CREATION STATEMENT #
print("2 CREATING ROLES")
session = initiate_sf_session("useradmin")
for index, row in roles_df.iterrows():
    session.sql("create or replace role {0}".format(row["Role"])).collect()
    session.sql("grant role {} to role sysadmin".format(row["Role"])).collect()

# 3 CLOSE SF SESSION #
session.close()

### OBJECTS ###

# 1 GET OBJECTS FROM DATA #
objects_df = read_setup_data("objects_data")
dbs_df = objects_df["Database"].drop_duplicates()

# 2 EXECUTE OBJECT CREATION STATEMENTS #
print("3 CREATING OBJECTS")
session = initiate_sf_session("sysadmin")
for index, value in dbs_df.items():
    session.sql("create or replace database {0}".format(value)).collect()
for index, row in objects_df.iterrows():
    session.sql("create or replace schema {0}.{1}".format(row["Database"], row["Schema"])).collect()

# 3 CLOSE SF SESSION #
session.close()

### VIRTUAL WAREHOUSES ###

# 1 GET WAREHOUSES FROM DATA #
warehouse_df = read_setup_data("vwarehouse_data")

# 2 EXECUTE WAREHOUSE CREATION STATEMENTS #
print("4 CREATING VIRTUAL WAREHOUSES")
session = initiate_sf_session("sysadmin")
for index, row in warehouse_df.iterrows():
    session.sql("""create or replace warehouse {0} with
    warehouse_type = '{1}'
    warehouse_size = {2}
    max_cluster_count = {3}
    min_cluster_count = {4}
    scaling_policy = {5}
    auto_suspend = {6}
    auto_resume = {7}
    initially_suspended = {8}""".format(row["Name"], row["Warehouse_Type"], row["Warehouse_Size"],\
                                        row["Max_Cluster_Count"], row["Min_Cluster_Count"], row["Scaling_Policy"],\
                                            row["Auto_Suspend"], row["Auto_Resume"], row["Initially_Suspended"])).collect()

# 3 CLOSE SF SESSION #
session.close()

### USERS ###

# 1 GET USERS FROM DATA #
users_df = read_setup_data("users_data")

# 2 EXECUTE USERS CREATION STATEMENTS #
print("5 CREATING USERS")
session = initiate_sf_session("useradmin")
for index, row in users_df.iterrows():
    session.sql("""create or replace user {0}
    password = '{1}'
    login_name = '{2}'
    display_name = '{3}'
    first_name = '{4}'
    last_name = '{5}'
    email = '{6}'
    must_change_password = {7}
    default_warehouse = {8}
    default_role = {9}""".format(row["Username"], row["Password"], row["Login_Name"], row["Display_Name"],\
                                 row["First_Name"], row["Last_Name"], row["Email"], row["Must_Change_Password"],\
                                    row["Default_Warehouse"], row["Default_Role"])).collect()

# 3 CLOSE SF SESSION #
session.close()

# 4 CREATING SANDBOXES #
session = initiate_sf_session("sysadmin")
for index, row in users_df.iterrows():
    if row['Sandbox']=="TRUE":
        session.sql("""create or replace schema rda.{0}""".format(row["Username"])).collect()
session.close()

### RESOURCE MONITORS ###

# 1 GET RM FROM DATA #
# Resource Monitors
rm_1_df = read_setup_data("rm_1_data")
# To be notified users
rm_2_df = read_setup_data("rm_2_data")
# Triggers
rm_3_df = read_setup_data("rm_3_data")

# 2 EXECUTE RESOURCE MONITORS STATEMENTS #
print("6 CREATING RESOURCE MONITORS")
session = initiate_sf_session("accountadmin")
for index, row in rm_1_df.iterrows():
    # Creating string of list of users to be notified
    list_users_to_notify = rm_2_df.loc[rm_2_df['Monitor_Name']==row['Monitor_Name']].User.values.tolist()
    # Creating string of list of triggers
    list_triggers = []
    filtered_triggers = rm_3_df.loc[rm_3_df['Monitor_Name']==row['Monitor_Name']]
    for index_1, row_1 in filtered_triggers.iterrows():
        list_triggers.append("on {0} percent do {1}".format(row_1['Percentage'], row_1['Action']))
    # Execute SQL
    session.sql("""create or replace resource monitor {0} with
    credit_quota = {1}
    frequency = {2}
    start_timestamp = {3}
    notify_users = ({4})
    triggers {5}""".format(row['Monitor_Name'], row['Credit_Quota'], row['Frequency'], row['Start_Timestamp'],\
                           ','.join(list_users_to_notify), ' '.join(list_triggers))).collect()

# 3 CLOSE SF SESSION #
session.close()

### PRIVILEGES ###

# 1 GET PRIVILEGES FROM DATA #
# Privileges on databases
privileges_db_df = read_setup_data("privileges_db_data")
# Privileges on schemas
privileges_schemas_df = read_setup_data("privileges_schemas_data")
# Privileges on warehouses
privileges_wh_df = read_setup_data("privileges_wh_data")

# 2 EXECUTE PRIVILEGES CREATION STATEMENTS #
print("7 CREATING PRIVILEGES")
session = initiate_sf_session("securityadmin")
# Create privileges on databases
for index, row in privileges_db_df.iterrows():
    session.sql("""grant {0} on database {1} to role {2}""".format(row['Privilege'], row['Database'],\
                                                                   row['Role'])).collect()
# Create privileges on schemas
for index, row in privileges_schemas_df.iterrows():
    session.sql("""grant {0} on schema {1}.{2} to role {3}""".format(row['Privilege'], row['Database'],\
                                                                   row['Schema'], row['Role'])).collect()
# Create privileges on warehouses
for index, row in privileges_wh_df.iterrows():
    session.sql("""grant {0} on warehouse {1} to role {2}""".format(row['Privilege'], row['Warehouse_Name'],\
                                                                   row['Role'])).collect()

# 3 CLOSE SF SESSION #
session.close()

### GRANTING ROLES ###

# 1 GET ROLES ASSIGNMENTS FROM DATA #
roles_assgm_df = read_setup_data("roles_assignments_data")

# 2 EXECUTE ROLES ASSIGNMENTS STATEMENTS #
print("8 ASSIGNING ROLES")
session = initiate_sf_session("securityadmin")
# Assigning roles to users
for index, row in roles_assgm_df.iterrows():
    session.sql("""grant role {0} to user {1}""".format(row['Role'], row['User'])).collect()
    
# 3 CLOSE SF SESSION #
session.close()

print("SETUP COMPLETE 100%")