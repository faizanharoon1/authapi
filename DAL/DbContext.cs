using Dapper;
using Dapper.Contrib.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MySql.Data.MySqlClient;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Transactions;
using DAL.Entities;

namespace DAL
{
    public interface IDbContext
    {
        Task<T> GetAsync<T>(int id) where T : class;
        Task<int> InsertAsync<T>(T insert) where T : class;
        Task<bool> UpdateAsync<T>(T insert) where T : class;
        Task<IEnumerable<T>> QueryAsyncWithRetry<T>(string query, object queryParameters, int? CommandTimeout = null);
        Task<T> QueryFirstOrDefaultAsync<T>(string query, object queryParameters);
        Task<int> ExecuteAsync(string query, object queryParameters, int? commandTimeout = null);
        Task<int> ExecuteAsyncWithRetry(string query, object queryParameters, int? CommandTimeout = null);
        Task<int> ExecuteSqlBulkCopy(DataTable sourceDataTable, string targetTableName, int BatchSize);
    }
    public class DbContext : IDbContext
    {
        IOptions<ConnectionStrings> _configuration;
        private IDefaultSQLPolicy _defaultSQLPolicy;
        private ILogger<DbContext> _logger;
        private readonly int timeOut = 30;

        public DbContext(IOptions<ConnectionStrings> configuration,
            IDefaultSQLPolicy defaultSQLPolicy, ILogger<DbContext> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _defaultSQLPolicy = defaultSQLPolicy;
        }
        public async Task<T> GetAsync<T>(int id) where T : class
        {
            try
            {
                using (MySqlConnection sqlconn = new MySqlConnection(_configuration.Value.AuthConnectionString))
                {
                    try
                    {
                        return await sqlconn.GetAsync<T>(id);
                    }
                    catch (SqlException ex)
                    {
                        Debug.WriteLine("Exception: {0}", ex.Message);
                        throw;
                    }
                    finally
                    {
                        sqlconn.Close();
                    }
                }

            }
            catch (Exception)
            {
                throw;
            }
        }
        public async Task<int> InsertAsync<T>(T insert) where T : class
        {
            try
            {
                using (MySqlConnection sqlconn = new MySqlConnection(_configuration.Value.AuthConnectionString))
                {
                    try
                    {
                        return await sqlconn.InsertAsync<T>(insert);
                    }
                    catch (SqlException ex)
                    {
                        Debug.WriteLine("Exception: {0}", ex.Message);
                        throw;
                    }
                    finally
                    {
                        sqlconn.Close();
                    }
                }

            }
            catch (Exception)
            {
                throw;
            }
        }
        public async Task<bool> UpdateAsync<T>(T insert) where T : class
        {
            try
            {
                using (MySqlConnection sqlconn = new MySqlConnection(_configuration.Value.AuthConnectionString))
                {
                    try
                    {
                        return await sqlconn.UpdateAsync<T>(insert);
                    }
                    catch (SqlException ex)
                    {
                        Debug.WriteLine("Exception: {0}", ex.Message);
                        throw;
                    }
                    finally
                    {
                        sqlconn.Close();
                    }
                }

            }
            catch (Exception)
            {
                throw;
            }
        }
        public async Task<T> QueryFirstOrDefaultAsync<T>(string query, object queryParameters)
        {
            try
            {

                object value = typeof(T);

                using (MySqlConnection sqlconn = new MySqlConnection(_configuration.Value.AuthConnectionString))
                {
                    try
                    {
                        value = await sqlconn.QueryFirstOrDefaultAsync<T>(query, queryParameters);
                    }
                    catch (SqlException ex)
                    {
                        Debug.WriteLine("Exception: {0}", ex.Message);
                        throw;
                    }
                    finally
                    {
                        sqlconn.Close();
                    }
                }

                return (T)Convert.ChangeType(value, typeof(T));
            }
            catch (Exception)
            {
                throw;
            }
        }

        public async Task<IEnumerable<T>> QueryAsync<T>(string query, object queryParameters)
        {
            try
            {

                using (MySqlConnection sqlconn = new MySqlConnection(_configuration.Value.AuthConnectionString))
                {
                    try
                    {
                        return await sqlconn.QueryAsync<T>(query, queryParameters);
                    }
                    catch (SqlException)
                    {
                        throw;
                    }
                    finally
                    {
                        sqlconn.Close();
                    }
                }
            }
            catch (Exception)
            {
                throw;
            }
        }
        public async Task<int> ExecuteAsync(string query, object queryParameters, int? commandTimeout)
        {
            try
            {
                int result = 0;


                using (MySqlConnection sqlconn = new MySqlConnection(_configuration.Value.AuthConnectionString))
                {
                    try
                    {
                        if (sqlconn.State == ConnectionState.Closed)
                        {
                            sqlconn.Open();
                        }
                        result = await sqlconn.ExecuteAsync(query, queryParameters, null, commandTimeout.GetValueOrDefault(timeOut));
                    }
                    catch (SqlException ex)
                    {
                        _logger.LogError("Caught SQL exception in ExecuteAsync {0}", ex);
                        throw;
                    }
                    finally
                    {
                        if (sqlconn.State == ConnectionState.Open)
                        {
                            sqlconn.Close();
                        }
                    }
                }

                return result;
            }
            catch (Exception)
            {
                throw;
            }
        }
        public async Task<int> ExecuteAsyncWithRetry(string query, object queryParameters, int? commandTimeout)
        {
            try
            {
                int result = 0;

                using (MySqlConnection sqlconn = new MySqlConnection(_configuration.Value.AuthConnectionString))
                {
                    try
                    {
                        if (sqlconn.State == ConnectionState.Closed)
                        {
                            sqlconn.Open();
                        }
                        result = await _defaultSQLPolicy.GetAsyncPolicy().ExecuteAsync(async () => await sqlconn.ExecuteAsync(query, queryParameters, null, commandTimeout.GetValueOrDefault(timeOut)));
                    }
                    catch (SqlException ex)
                    {
                        _logger.LogError("Caught SQL exception in ExecuteAsync {0}", ex);
                        throw;
                    }
                    finally
                    {
                        if (sqlconn.State == ConnectionState.Open)
                        {
                            sqlconn.Close();
                        }
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError("Caught Exception in ExecuteAsync {0}", ex);
                throw;
            }
        }
        public async Task<IEnumerable<T>> QueryAsyncWithRetry<T>(string query, object queryParameters, int? commandTimeout)
        {
            try
            {

                using (MySqlConnection sqlconn = new MySqlConnection(_configuration.Value.AuthConnectionString))
                {
                    try
                    {
                        if (sqlconn.State == ConnectionState.Closed)
                        {
                            sqlconn.Open();
                        }
                        return await _defaultSQLPolicy.GetAsyncPolicy().ExecuteAsync(async () => await sqlconn.QueryAsync<T>(query, queryParameters, null, commandTimeout.GetValueOrDefault(timeOut)));
                    }
                    catch (SqlException ex)
                    {
                        _logger.LogError("Caught SQL exception in ExecuteAsync {0}", ex);
                        throw;
                    }
                    finally
                    {
                        if (sqlconn.State == ConnectionState.Open)
                        {
                            sqlconn.Close();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Caught Exception in ExecuteAsync {0}", ex);
                throw;
            }
        }

        public async Task<int> ExecuteSqlBulkCopy(DataTable sourceDataTable, string targetTableName, int BatchSize)
        {
            try
            {
                int result = 0;
                if (string.IsNullOrEmpty(targetTableName))
                {
                    throw new Exception("Destination table does not exist for this Sql bulk copy statement.");
                }

                using (TransactionScope scope = new TransactionScope(TransactionScopeAsyncFlowOption.Enabled))
                {
                    using (SqlBulkCopy copy = new SqlBulkCopy(_configuration.Value.AuthConnectionString))
                    {
                        try
                        {
                            foreach (DataColumn col in sourceDataTable.Columns)
                            {
                                copy.ColumnMappings.Add(col.ColumnName, col.ColumnName);
                            }

                            copy.DestinationTableName = targetTableName;
                            copy.BatchSize = BatchSize;
                            copy.BulkCopyTimeout = (int)TimeSpan.FromMinutes(5).TotalSeconds;
                            //save to the DB
                            await copy.WriteToServerAsync(sourceDataTable);
                            result = sourceDataTable.Rows.Count;
                        }
                        catch (SqlException)
                        {
                            throw;
                        }
                        finally
                        {
                            copy.Close();
                        }
                    }

                    scope.Complete();
                }

                return result;
            }
            catch (Exception)
            {
                throw;
            }
        }
    }


}
