function Remove-ABEdgeBookmarks {
	<#
	.SYNOPSIS
	Removes OEM-added Edge bookmarks from the default user profile.
	#>
	[CmdletBinding()]
	param ()

	$bookmarks = "$(Get-ABDefaultUserProfilePath)\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
	if (Test-Path $bookmarks) {
		Write-ABLog 'Removing Edge bookmarks file from default profile'
		Remove-Item $bookmarks -Force
	}
	$bookmarksRegPath = 'HKLM:\SOFTWARE\Microsoft\MicrosoftEdge\Main\FavoriteBarItems'
	if (Test-Path $bookmarksRegPath) {
		Remove-Item -Path $bookmarksRegPath -Recurse -Force
		Write-ABLog 'OEM Edge bookmarks were detected and removed successfully'
	} else {
		Write-ABLog 'No OEM Edge bookmarks were detected'
	}
}
