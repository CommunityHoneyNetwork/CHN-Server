import pytest
import subprocess
import testinfra
import os
import time


# scope='session' uses the same container for all the tests;
# scope='function' uses a new container per test function.
@pytest.fixture(scope='session')
def host(request):
    if 'CI_BUILD_TOKEN' in os.environ:
        # Use existing if we are in a CI process
        docker_id = subprocess.check_output(
            ['docker', 'run', '-d', os.environ['CI_APPLICATION_TAG']]
             ).decode().strip()
        # return a testinfra connection to the container
        yield testinfra.get_host("docker://" + docker_id)

    else:
        # build locally
        subprocess.check_call([
            'docker', 'build', '-t', 'chn-server-test',
            '-f', 'Dockerfile-ubuntu', '.'])
        # run a container
        docker_id = subprocess.check_output(
            ['docker', 'run', '-d', 'chn-server-test']).decode().strip()
        # return a testinfra connection to the container
        yield testinfra.get_host("docker://" + docker_id)

    # at the end of the test suite, destroy the container
    subprocess.check_call(['docker', 'rm', '-f', docker_id])


def test_ports_listening(host):
    print("Testing testing")
    # Sleep a few seconds until things come up
    time.sleep(15)
    print(host.check_output("netstat -anlpt"))
    print(host.socket.get_listening_sockets())
    assert host.socket("tcp://0.0.0.0:80").is_listening
    assert host.socket("tcp://0.0.0.0:443").is_listening
