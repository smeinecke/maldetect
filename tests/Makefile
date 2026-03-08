BATSMAN_OS_MODERN := debian12 rocky9 ubuntu2404
BATSMAN_OS_LEGACY := centos7 rocky8 ubuntu2004
BATSMAN_OS_DEEP   := centos6
BATSMAN_OS_EXTRA  := rocky10 yara-x
BATSMAN_OS_ALL    := $(BATSMAN_OS_MODERN) $(BATSMAN_OS_LEGACY) $(BATSMAN_OS_DEEP) $(BATSMAN_OS_EXTRA)
BATSMAN_RUN_TESTS := ./run-tests.sh
BATSMAN_PROJECT   := lmd

include infra/include/Makefile.tests

# UAT override: --init reaps orphaned background processes (monitor mode tests),
# --stop-timeout 3 ensures fast container shutdown when background maldet processes
# linger after bats exits.
uat:
	BATSMAN_DOCKER_FLAGS="--init --stop-timeout 3" $(BATSMAN_RUN_TESTS) -- $(BATSMAN_UAT_PATH)
