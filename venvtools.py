import os


def activate(basedir: str) -> None:
    """ Look for and activate a virtualenv within the given base directory """

    for dir_name in [f.path for f in os.scandir(basedir) if f.is_dir()]:
        activate_dir = os.path.join(basedir, dir_name, 'bin', 'activate_this.py')
        if os.path.isfile(activate_dir):
            print(f'Activating virtualenv in {dir_name}')
            try:
                exec(open(activate_dir).read(), {'__file__': activate_dir})
            except Exception as exc:
                print('Could not run activate script. Module imports will most likely fail.', exc)
