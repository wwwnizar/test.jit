import json
import logging
import os
import sys

from boxsdk import Client
from boxsdk import JWTAuth


class BoxClient(object):
    def __init__(self):
        self.client = None
        self.logger = logging.getLogger(__name__)

    def get_client(self, box_config_filename=os.getenv('GD_BOX_CONFIG_FILE')):
        '''
        Create box client from box configuration file

        box_config_filename path to the box config file
        '''
        if self.client:
            return self.client

        # the custom Box app MUST be authorized from admin console
        with open(box_config_filename) as box_config_file:
            data = json.load(box_config_file)
            auth = JWTAuth(
                client_id=data['boxAppSettings']['clientID'],
                client_secret=data['boxAppSettings']['clientSecret'],
                enterprise_id=data['enterpriseID'],
                jwt_key_id=data['boxAppSettings']['appAuth']['publicKeyID'],
                rsa_private_key_passphrase=data['boxAppSettings']['appAuth']['passphrase'].encode(),
                rsa_private_key_data=data['boxAppSettings']['appAuth']['privateKey'],
            )
            self.client = Client(auth)

        return self.client

    def upload_file(self, box_folder_id: str, filename: str):
        '''
        Upload local with filename to box folder. The base file name for the incoming
        file would be used as the file name in box folder.

        box_folder_id the id for certain box folder, you can obtain it from URL,
                      e.g. https://ibm.ent.box.com/folder/<box_folder_id>
        filename the full name of the local file to be upload.
        '''
        if not os.path.isfile(filename):
            self.logger.warning(f'{filename} is not a regular file')
            raise Exception(f'{filename} is not a regular file')

        client = self.get_client()
        root_folder = client.folder(box_folder_id).get()

        self.logger.info(f'root box folder: {root_folder.name}')

        # lookup existing files
        items = root_folder.get_items()
        existing_files_map = {
            item.name: item.object_id
            for item in items if item.type == 'file'
        }

        basename = os.path.basename(filename)
        # upload file
        if basename in existing_files_map:  # file exist. upload new version
            object_id = existing_files_map[basename]
            updated_file = client.file(object_id).update_contents(filename)
            self.logger.info(f'updated {updated_file.name} on {updated_file.modified_at}')
        else:   # create new file
            uploaded_file = root_folder.upload(filename)
            self.logger.info(f'uploaded {uploaded_file.name} on {uploaded_file.created_at}')


if __name__ == '__main__':  # pragma: no cover
    box_folder_id = sys.argv[1]
    filename = sys.argv[2]

    BoxClient = BoxClient()
    BoxClient.upload_file(box_folder_id, filename)
