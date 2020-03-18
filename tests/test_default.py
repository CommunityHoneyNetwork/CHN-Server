import pytest
import subprocess
import testinfra
import time
import sys


# scope='session' uses the same container for all the tests;
# scope='function' uses a new container per test function.
@pytest.fixture(scope='session')
def host(request):
    # build locally
    sys.stderr.write("Building locally\n")
    subprocess.check_call([
        'docker', 'build', '-t', 'chn-server-test',
        '-f', 'Dockerfile', '.'])
    # run a container
    docker_id = subprocess.check_output(
        ['docker', 'run', '-d', 'chn-server-test']).decode().strip()
    # return a testinfra connection to the container
    yield testinfra.get_host("docker://" + docker_id)

    subprocess.check_output(["docker", "exec", docker_id, "date"])

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
