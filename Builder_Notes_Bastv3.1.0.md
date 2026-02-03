1. Do analyze the 'Feature List' tab on http://hermasnet.local/wp-admin/admin.php?page=vapt-domain-admin
  - Reduce the Width of 'Include Column' by 40%, and Increase the Width of 'Title' Column on the Features List Tab
  - Remove Redundant "Verification Engine" button from the Include Column,

2. On Workbench Design Hub Modal form, we need to 
  - For Control Type "alert", we should assume "label" as type of "Icon Type", and "message" should be treated like actual "content" is being implemented.
  - on the http://hermasnet.local/wp-admin/admin.php?page=vapt-builder, where the Implementation of the Feature's actually displayed, follow the instructions on here: https://prnt.sc/H6ZM2PTWmZKP
    - Remove the `tooltip`, and display its content right below the 'Feature Name/Title' heading.
    - Tie the `info/warning box' info with the Toggle [used to enable/disable the feature], and should only be displayed when the Feature is Disabled.
