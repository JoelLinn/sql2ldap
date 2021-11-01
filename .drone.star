# Automatically builds docker images and pushes them to the registry.
# Required drone secrets:
#   - docker_repo       eg. 'joellinn/php'
#   - docker_username   user with write permissions to repo
#   - docker_password   password of the user

def main(ctx):
    return [
        {
            'kind': 'pipeline',
            'type': 'docker',
            'name': 'docker-hub',
            'steps':
            [
                {
                    'name': 'build-push',
                    'image': 'plugins/docker',
                    'settings': {
                        'tags': ['latest'],
                        'repo': {'from_secret': 'docker_repo'},
                        'username': {'from_secret': 'docker_username'},
                        'password': {'from_secret': 'docker_password'},
                    },
                },
            ],
            'trigger':
            {
                'branch': ['master'],
                'event': ['push']
            },
        },
    ]
