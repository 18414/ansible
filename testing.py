fomr ansible.module_utils.basic import *
if _name_ == '_main_':
   fields = { 
   "reyansh": {"required": True, "type": "str"}
  }
 module = AnsibleModule(argument_spec=fields)
 yourName = os.path.expanduser(module.params['reyansh'])
 newName = firstProg(reyansh)
 module.exit_json(msg=newName)

