<?php

/* needed exceptions */
class URLAliasException extends Exception {}

class URLAliasEmptyStringURLAliasException       extends URLAliasException {}
class URLAliasNotAnArrayException                extends URLAliasException {}
class URLAliasIncorrectGenericRouteFlagException extends URLAliasException {}
class URLAliasNegativeRoutePriorityException     extends URLAliasException {}

/* API use example
 *
 * $dsn      = 'mysql:dbname=modurlalias;host=localhost';
 * $user     = 'user';
 * $password = 'password';
 *
 * $pdo = new PDO($dsn, $user, $password);
 *
 * $urlAlias = new URLAlias( $pdo );
 * $urlAlias->source        = "toto";
 * $urlAlias->module        = "module";
 * $urlAlias->view          = "view.py";
 * $urlAlias->parameters    = array( 'p1' => 'valueOfP1',
 *                                   'p2' => 'valueOfP2' );
 *
 *
 * $urlAlias->addNew();
 */
class URLAlias
{
    private $PDO;

    private $tableName;

    private $tableFields = array();

    public function __construct( PDO $pdo, $tableName = 'urlalias' )
    {
        $this->PDO = $pdo;

        $this->tableName = $tableName;

        $this->tableFields['source']         = null;
        $this->tableFields['redirect_to']    = null;
        $this->tableFields['module']         = null;
        $this->tableFields['view']           = null;
        $this->tableFields['parameters']     = null;
        $this->tableFields['generic_route']  = 0;
        $this->tableFields['route_priority'] = null;
    }

    public function __set( $name, $value )
    {
        switch( $name )
        {
            case 'source' :
            case 'module' :
            case 'view'   :
                if( $value == '' )
                    throw new URLAliasEmptyStringException( 'The field ' . $name . ' can not be empty' );
                else
                    $this->tableFields[$name] = $value;
            break;

            case 'redirectTo' :
                $this->tableFields['redirect_to'] = $value;
            break;

            case 'parameters'    :
                if( !is_array( $value ) )
                    throw new URLAliasNotAnArrayException( 'The parameters are not defined in an array' );

                if( count( $value ) > 0 )
                {
                    /* add a '=' between the name and the value of each param */
                    $paramList = array();
                    foreach( $value as $paramName => $paramValue )
                        $paramList[] = $paramName. '=' . $paramValue;

                    /* if this is a generic route then the & must be escaped */
                    /* not to break the regex */
                    if( $this->tableFields['generic_route'] == 1 )
                        $glue = '\&';
                    else
                        $glue = '&';

                    $this->tableFields[$name] = join( $glue, $paramList );
                }
            break;

            case 'genericRoute'  :
                if( $value < 0 or $value > 1 )
                    throw new URLAliasIncorrectGenericRouteFlagException( 'The value ' . $value . ' for the generic route flag is either 1 or 0' );

                $this->tableFields['generic_route'] = (int)$value;
            break;

            case 'routePriority' :
                if( $this->tableFields['generic_route'] < 0 )
                    throw new URLAliasNegativeRoutePriorityException( 'the priority for a generic route must be > 0' );

                if( $this->tableFields['generic_route'] == 0 )
                    $this->tableFields['route_priority'] = null;
            break;
        }
    }

    public function addNew()
    {
        $insertQuery = $this->buildInsertQuery();
        $stmt = $this->PDO->prepare( $insertQuery );
        return $stmt->execute( $this->tableFields );
    }

    private function buildInsertQuery()
    {
        return  'INSERT INTO ' . $this->tableName
              . ' VALUES( :source,
                          :redirect_to,
                          :module,
                          :view,
                          :parameters,
                          :generic_route,
                          :route_priority )';
    }
}

?>