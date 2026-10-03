"""Skip publication when VERSION already exists; never overwrite a release."""
import os
from pathlib import Path
import urllib.error
from publish_image import hub, validate_release
from publish_release import repository_visibility, require_manual_dispatch


def release_needed(image, version, revision, username, secret):
    validate_release(image, version, revision)
    token = hub('auth/token', payload={'identifier': username, 'secret': secret})['access_token']
    repository_visibility(hub('repositories/' + image + '/', token), 'is_private', 'Docker Hub')
    try:
        hub('repositories/' + image + '/tags/' + version + '/', token)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        return True
    return False


if __name__ == '__main__':
    require_manual_dispatch(True)
    publish = release_needed(os.environ['DOCKERHUB_IMAGE'], Path('VERSION').read_text().strip(),
        os.environ['GITHUB_SHA'], os.environ['DOCKERHUB_USERNAME'], os.environ['DOCKERHUB_TOKEN'])
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('publish=' + str(publish).lower() + '\n')
    print('New version requires publication' if publish else 'Version already published; keeping existing images unchanged')
