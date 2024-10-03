#! /usr/bin/env python

import subprocess
import os

from setuptools import setup, find_packages
from setuptools.command.sdist import sdist


class eo_sdist(sdist):
    def run(self):
        print("creating VERSION file")
        if os.path.exists('VERSION'):
            os.remove('VERSION')
        version = get_version()
        version_file = open('VERSION', 'w')
        version_file.write(version)
        version_file.close()
        sdist.run(self)
        print("removing VERSION file")
        if os.path.exists('VERSION'):
            os.remove('VERSION')


def get_version():
    '''Use the VERSION, if absent generates a version with git describe, if not
       tag exists, take 0.0- and add the length of the commit log.
    '''
    if os.path.exists('VERSION'):
        with open('VERSION', 'r') as v:
            return v.read()
    if os.path.exists('.git'):
        p = subprocess.Popen(['git', 'describe', '--dirty=.dirty','--match=v*'], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        result = p.communicate()[0]
        if p.returncode == 0:
            result = result.decode('ascii').strip()[1:]  # strip spaces/newlines and initial v
            if '-' in result:  # not a tagged version
                real_number, commit_count, commit_hash = result.split('-', 2)
                version = '%s.post%s+%s' % (real_number, commit_count, commit_hash)
            else:
                version = result
            return version
        else:
            return '0.0.post%s' % len(
                subprocess.check_output(
                    ['git', 'rev-list', 'HEAD']).splitlines())
    return '0.0'

setup(name="django-kerberos-client",
      version=get_version(),
      license="AGPLv3",
      description="Kerberos authentication module for Django",
      long_description=open('README').read(),
      url="https://www.acsone.eu/",
      author="Acsone",
      author_email="info@acsone.eu",
      maintainer="Geoffrey Piraprez",
      maintainer_email="geoffrey.praprez@acsone.eu",
      packages=find_packages('src'),
      zip_safe=False,
      include_package_data=True,
      install_requires=[
          'six',
          'django>=5.0.0',
          'pykerberos',
      ],
      package_dir={
          '': 'src',
      },
      package_data={
          'django_kerberos-client': [
              'templates/django_kerberos_client/*.html',
              'static/js/*.js',
          ],
      },
      cmdclass={'sdist': eo_sdist})
