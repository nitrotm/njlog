#!/bin/sh

ant -Dbuildopt_debug="off" -Dinternal_buildopt_debuglevel="" -Dinternal_buildopt_optimize="on" build

exit $?
