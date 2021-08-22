Improved quick hack to convert a 1pif (1Password export) to kdbx (KeePass).


Install dependencies
--------------------

    pipenv install


Run converter
-------------

    pipenv run ./convert.py infile.1pif


Basic 1Password 1PIF structure
------------------------------

```json
{
    'contentsHash': 'cf89d854',
    'createdAt': 1617646219,
    'location': 'https://domain.com/',
    'locationKey': 'domain.com',
    'openContents': {
        'tags': ['Tag1', 'Tag2']
    },
    'secureContents': {
        'URLs': [
            {'label': 'website', 'url': 'https://domain.com/'}
        ],
        'fields': [
            {
                'designation': 'username',
                'name': 'name_of_username_field_on_website',
                'type': 'T',
                'value': 'john.doe'
            },
            {
                'designation': 'password',
                'name': 'name_of_password_field_on_website',
                'type': 'P',
                'value': 'ultrasecurepassword'
            }
        ],
        'notesPlain': 'This is a note.',
        'sections': [
            {
                'fields': [
                    {
                        'inputTraits': {'autocapitalization': 'Words'},
                        'k': 'string',
                        'n': 'org_name',
                        't': 'group',
                        'v': 'My Organisation'
                    },
                    {
                        'inputTraits': {'autocapitalization': 'Words'},
                        'k': 'string',
                        'n': 'member_name',
                        't': 'member name',
                        'v': 'John Doe'
                    }
                ]
                'name': '',
                'title': ''
            },
            {
                'name': 'linked items',
                'title': 'Related Items'
                // no "fields" structure = empty section
            }
        ]
    },
    'scope': 'Never',
    'securityLevel': 'SL5',
    'title': 'My secret password',
    'typeName': 'webforms.WebForm',
    'updatedAt': 1618176026,
    'uuid': 'ysd77pxq4zghhodfbo47cewudy'}
 ```

Fields inside sections can be of various types: text, url, email, address, date, month/year, otp, password or a phone number.

Also there are different typeName values that define different field presets.


Basic KeePass structure
-----------------------

```
- UUID
- Title
- UserName
- Password
- URL
- Tags
- IconID
- Times
- History
- Notes
- custom fields
```

Default fields are text. Custom fields can also only be of type text - either hidden (password field) or not.
