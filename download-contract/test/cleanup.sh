SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SOURCE_ROOT="$(realpath ${SCRIPTDIR}/..)"
rm -f ${SCRIPTDIR}/*_db ${SCRIPTDIR}/*-lock ${SCRIPTDIR}/test_context.toml