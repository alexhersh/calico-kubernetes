.PHONY: all binary ut clean

SRCDIR=calico_kubernetes
BUILD_DIR=build_calico_kubernetes
BUILD_FILES=$(BUILD_DIR)/Dockerfile $(BUILD_DIR)/requirements.txt

default: all
all: binaries test
binaries: binary policybin
test: ut
policy_agent: policyagent.created

# Build a new docker image to be used by binary or tests
kubernetesbuild.created: $(BUILD_FILES)
	cd $(BUILD_DIR); docker build -t calico/kubernetes-build .
	touch kubernetesbuild.created

binary: kubernetesbuild.created
	mkdir -p dist
	chmod 777 `pwd`/dist

	# Build the kubernetes plugin
	docker run \
	-u user \
	-v `pwd`/calico_kubernetes:/code/calico_kubernetes \
	-v `pwd`/common:/code/common \
	-v `pwd`/dist:/code/dist \
	-e PYTHONPATH=/code \
	calico/kubernetes-build pyinstaller calico_kubernetes/calico_kubernetes.py -a -F -s --clean

policybin: kubernetesbuild.created
	mkdir -p policy_agent/dist
	chmod 777 `pwd`/policy_agent/dist

	# Build the kubernetes policy agent
	docker run \
	-u user \
	-v `pwd`/policy_agent:/code/policy_agent \
	-v `pwd`/common:/code/common \
	-v `pwd`/policy_agent/dist:/code/dist \
	-e PYTHONPATH=/code \
	calico/kubernetes-build pyinstaller policy_agent/policy_agent.py -a -F -s --clean

ut: kubernetesbuild.created
	docker run --rm \
	-v `pwd`/calico_kubernetes:/code/calico_kubernetes \
	-v `pwd`/common:/code/common \
	-v `pwd`/nose.cfg:/code/nose.cfg \
	calico/kubernetes-build bash -c \
	'>/dev/null 2>&1 & PYTHONPATH=/code \
	nosetests calico_kubernetes/tests -c nose.cfg'

# UT runs on Cicle
ut-circle: binary
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
	-v `pwd`/calico_kubernetes:/code/calico_kubernetes \
	-v `pwd`/common:/code/common \
	-v `pwd`/nose.cfg:/code/nose.cfg \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
	calico/kubernetes-build bash -c \
	'>/dev/null 2>&1 & PYTHONPATH=/code \
	nosetests calico_kubernetes/tests -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

clean:
	-rm -f *.created
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-rm -rf policy_agent/dist
	-docker rmi -f calico/kubernetes-build
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes

