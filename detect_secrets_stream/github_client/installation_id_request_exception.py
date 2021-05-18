class InstallationIDRequestException(Exception):
    """ Custom exception for when requsting the app installation id from a private repo
        fails. Typically indicates that the app is not installed on the repo. """
