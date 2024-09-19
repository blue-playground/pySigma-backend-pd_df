from .pd_df import PandasDataFramePythonBackend

backends = {  # Mapping between backend identifiers and classes. This is used by the pySigma plugin system to recognize backends and expose them with the identifier.
    "pd_df": PandasDataFramePythonBackend,
}
