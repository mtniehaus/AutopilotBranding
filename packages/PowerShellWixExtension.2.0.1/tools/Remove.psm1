# Created by Alexander Köplinger, 2013

function Remove-Changes
{
    param(
        [parameter(Position = 0, Mandatory = $true)]
        [Microsoft.Build.Evaluation.Project]$msBuildProj
    )

    #TODO: this can probably be improved
    $wixToolPathProperties = $msBuildProj.Xml.AllChildren | Where-Object { $_.Include -eq 'PowerShellWixExtension' }
   
    if ($wixToolPathProperties)
    {
        foreach($item in $wixToolPathProperties)
        {
            $itemGroup = $item.Parent
            $itemGroup.RemoveChild($item)
        }
    }
}
